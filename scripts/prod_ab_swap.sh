#!/usr/bin/env bash
# prod_ab_swap.sh — Этап 2: кратковременная подмена ipt_NETFLOW -> xdpflowd.
#
# Что делает (в порядке действий):
#   1) Проверяет окружение. Не трогает ничего, если что-то не сходится.
#   2) Сохраняет полный backup правил iptables в /root/iptables-save-before-*.txt.
#   3) Находит точное правило ipt_NETFLOW (`-A PREROUTING -i <iface> -j NETFLOW`)
#      в нужной таблице (raw/mangle/nat). Выходит, если правил 0 или больше 1.
#   4) Ставит trap, который ОБЯЗАТЕЛЬНО восстанавливает правило на любом выходе
#      (normal exit, INT, TERM, ошибка, kill парента по SSH).
#   5) Удаляет правило iptables (ipt_NETFLOW перестаёт получать пакеты,
#      но модуль остаётся загружен — откат моментальный).
#   6) Запускает xdpflowd с NFv9 на РЕАЛЬНЫЕ destination'ы ipt_NETFLOW
#      (по умолчанию 127.0.0.1:9996,127.0.0.1:9999). goflow2/nfcapd/ClickHouse
#      начинают получать данные ОТ xdpflowd вместо ipt_NETFLOW.
#   7) Watchdog: каждые 10 с — процесс жив; рост total_packets/flows/records/packets_out в логе.
#      Долгий «тишина» в логе при живом демоне: см. WATCHDOG_STALL_SEC (default 120s).
#      WATCHDOG_STRICT=0 — только предупреждение, без emergency exit.
#   8) Через $DURATION секунд корректно останавливает xdpflowd.
#   9) Trap возвращает правило iptables. Проверяет, что вернулось.
#
# Риск и гарантии:
#   * Если вам нужно срочно вернуть всё назад — нажмите Ctrl+C или kill -TERM.
#     Trap сработает и на SIGHUP (обрыв SSH-сессии).
#   * Если по какой-то причине trap не сработал — используйте prod_restore.sh
#     (его можно запустить вручную с того же хоста, он умеет восстанавливаться
#     из backup-файла).
#
# Запуск:
#   sudo ./scripts/prod_ab_swap.sh [duration_sec] [iface] [nf_dsts]
# По умолчанию: 600 сек (10 минут), enp5s0d1, 127.0.0.1:9996,127.0.0.1:9999.
#
# XDP action:
#   XDP_ACTION=pass (default) — аккаунтить и пускать пакет дальше в kernel stack
#                                (безопасно, для A/B теста точности).
#   XDP_ACTION=drop           — аккаунтить и дропать. ТОЛЬКО на SPAN/mirror
#                                интерфейсе (enp5s0d1). Реальная экономия CPU.
#
#   sudo XDP_ACTION=drop ./scripts/prod_ab_swap.sh 600 enp5s0d1
#
# Пример "репетиции" (ничего не меняет, печатает план):
#   sudo ./scripts/prod_ab_swap.sh --dry-run

set -euo pipefail

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" || "${1:-}" == "-n" ]]; then
  DRY_RUN=1
  shift
fi

DURATION="${1:-600}"
IFACE="${2:-enp5s0d1}"
NF_DSTS="${3:-127.0.0.1:9996,127.0.0.1:9999}"

# XDP action for accounted IP packets: pass (safe, default) | drop (SPAN/mirror only).
# drop — реальная экономия CPU, но пакеты не дойдут до kernel stack.
XDP_ACTION="${XDP_ACTION:-pass}"
case "$XDP_ACTION" in
  pass|drop) ;;
  *) echo "ERROR: XDP_ACTION must be 'pass' or 'drop' (got: $XDP_ACTION)" >&2; exit 1;;
esac

# XDP load mode: native (fast, runs inside mlx4_en driver) |
#                generic (slower, runs after netif_receive_skb in the kernel).
# On mlx4_en + kernel 5.10 the native XDP_DROP path appears broken
# (HW fifo drops skyrocket). Generic mode bypasses mlx4_en XDP code
# entirely — useful as a diagnostic to confirm whether the bottleneck
# is inside the driver or deeper in the kernel RX path.
XDP_MODE="${XDP_MODE:-native}"
case "$XDP_MODE" in
  native|generic) ;;
  *) echo "ERROR: XDP_MODE must be 'native' or 'generic' (got: $XDP_MODE)" >&2; exit 1;;
esac

# Safety: если $IFACE выглядит как обычный роутинг-интерфейс (есть IP/маршруты),
# не даём запустить drop. Исключение — каноничный mirror enp5s0d1.
if [[ "$XDP_ACTION" == "drop" && "$IFACE" != "enp5s0d1" ]]; then
  if ip -4 addr show dev "$IFACE" 2>/dev/null | grep -q 'inet '; then
    echo "ERROR: $IFACE has IPv4 address — refusing XDP_ACTION=drop on non-SPAN interface" >&2
    echo "       drop only supported on enp5s0d1 or pass-through addressless interfaces" >&2
    exit 1
  fi
fi

# Hard cap — нельзя запустить на сутки случайно
MAX_DURATION=3600
if (( DURATION > MAX_DURATION )); then
  echo "ERROR: duration=$DURATION > $MAX_DURATION (hard cap)" >&2
  exit 1
fi

# Watchdog (env): крупные карты flow / редкие строки в логе могут давать 30+ с без роста метрик
# при живом xdpflowd — слишком короткое окно = ложный emergency restore.
#   WATCHDOG_WARMUP_SEC  — с начала сессии не считать «застой» (default 60)
#   WATCHDOG_STALL_SEC  — подряд без роста ни одного из tp/fm/rec/out (default 120)
#   WATCHDOG_STRICT=0  — при «застое» только WARN, не exit (процесс всё ещё убивается по DURATION/Ctrl+C)
WATCHDOG_WARMUP_SEC="${WATCHDOG_WARMUP_SEC:-60}"
WATCHDOG_STALL_SEC="${WATCHDOG_STALL_SEC:-120}"
WATCHDOG_STRICT="${WATCHDOG_STRICT:-1}"
if ! [[ "$WATCHDOG_STALL_SEC" =~ ^[0-9]+$ ]] || (( WATCHDOG_STALL_SEC < 30 )); then
  echo "ERROR: WATCHDOG_STALL_SEC must be integer >= 30" >&2
  exit 1
fi
WATCHDOG_STALL_INTERVALS=$(( (WATCHDOG_STALL_SEC + 9) / 10 ))

# NetFlow exporter timing (env): shorter active timeout helps short A/B tests
# verify ClickHouse continuity; larger shutdown grace lets final flush finish
# on multi-million flow maps instead of SIGKILL.
XDP_NF_ACTIVE="${XDP_NF_ACTIVE:-1800s}"
XDP_NF_IDLE="${XDP_NF_IDLE:-15s}"
XDP_NF_TEMPLATE_INTERVAL="${XDP_NF_TEMPLATE_INTERVAL:-60s}"
XDP_SHUTDOWN_GRACE="${XDP_SHUTDOWN_GRACE:-20}"
if ! [[ "$XDP_SHUTDOWN_GRACE" =~ ^[0-9]+$ ]] || (( XDP_SHUTDOWN_GRACE < 20 )); then
  echo "ERROR: XDP_SHUTDOWN_GRACE must be integer >= 20" >&2
  exit 1
fi

# mlx4 native XDP may need memory compaction before attach, but it must never
# run after the ipt_NETFLOW rule is removed: compact_memory can stall on hosts
# under pressure. Keep it bounded and allow smoke tests to skip it.
SKIP_MEMORY_PREP="${SKIP_MEMORY_PREP:-0}"
MEMORY_PREP_TIMEOUT="${MEMORY_PREP_TIMEOUT:-10}"
case "$SKIP_MEMORY_PREP" in 0|1) ;; *) echo "ERROR: SKIP_MEMORY_PREP must be 0 or 1" >&2; exit 1;; esac
if ! [[ "$MEMORY_PREP_TIMEOUT" =~ ^[0-9]+$ ]] || (( MEMORY_PREP_TIMEOUT < 1 )); then
  echo "ERROR: MEMORY_PREP_TIMEOUT must be integer >= 1" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TS="$(date +%Y%m%d_%H%M%S)"
WORKDIR="/tmp/xdpflowd_abswap_$TS"
IPT_BACKUP="/root/iptables-save-before-$TS.txt"
LOG_XDP="$WORKDIR/xdpflowd.log"
JSON_OUT="$WORKDIR/xdpflowd.ndjson"
STATE_FILE="$WORKDIR/state.env"     # сюда пишем всё, что нужно для восстановления

mkdir -p "$WORKDIR"

# ---------- проверки ----------
need_cmd() { command -v "$1" >/dev/null || { echo "ERROR: missing $1" >&2; exit 1; }; }
need_cmd iptables
need_cmd iptables-save
need_cmd iptables-restore
need_cmd clang
need_cmd ss

# ---------- Go >= 1.21 (нужен для log/slog, io/fs, maps, slices) ----------
go_ver_ok() {
  local v major minor
  v=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
  [[ -n "$v" ]] || return 1
  major=${v%%.*}
  minor=${v#*.}; minor=${minor%%.*}
  if (( major > 1 )) || (( major == 1 && minor >= 21 )); then return 0; fi
  return 1
}
if ! command -v go >/dev/null || ! go_ver_ok; then
  for cand in /usr/local/go/bin /opt/go/bin /usr/lib/go-1.22/bin /usr/lib/go-1.23/bin /usr/lib/go-1.24/bin; do
    if [[ -x "$cand/go" ]]; then
      OLD_PATH="$PATH"
      export PATH="$cand:$PATH"
      if go_ver_ok; then
        echo "[env] using Go from $cand ($(go version 2>/dev/null | awk '{print $3}'))"
        break
      else
        export PATH="$OLD_PATH"
      fi
    fi
  done
fi
if ! command -v go >/dev/null || ! go_ver_ok; then
  cur=$(go version 2>/dev/null | awk '{print $3}' || echo none)
  echo "ERROR: no Go >= 1.21 in PATH (found: $cur)" >&2
  echo "       Install Go 1.22+: https://go.dev/dl/" >&2
  echo "       Or prepend its bin dir: export PATH=/usr/local/go/bin:\$PATH" >&2
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root" >&2
  exit 1
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "ERROR: interface $IFACE not found" >&2
  exit 1
fi

# ---------- ОБЯЗАТЕЛЬНЫЙ baseline snapshot ----------
# Гарантия отката: делаем полный слепок рабочей схемы (iptables, sysctl,
# модули, порты, docker, ethtool, NIC counters). Если snapshot свежее
# часа — переиспользуем; иначе создаём новый.
BASELINE_DIR=""
LATEST_LINK="/root/xdpflowd_baseline_latest"
if [ -L "$LATEST_LINK" ] && [ -d "$LATEST_LINK" ]; then
  age_s=$(( $(date +%s) - $(stat -c %Y "$LATEST_LINK" 2>/dev/null || echo 0) ))
  if (( age_s < 3600 )); then
    BASELINE_DIR=$(readlink -f "$LATEST_LINK")
    echo "[$(date +%T)] reusing fresh baseline: $BASELINE_DIR (${age_s}s old)"
  fi
fi
if [ -z "$BASELINE_DIR" ]; then
  echo "[$(date +%T)] creating fresh baseline snapshot..."
  "$REPO_ROOT/scripts/prod_snapshot.sh" "$IFACE" > "$WORKDIR/baseline_snapshot.log" 2>&1
  BASELINE_DIR=$(readlink -f "$LATEST_LINK")
  echo "[$(date +%T)] baseline: $BASELINE_DIR"
fi
if [ ! -d "$BASELINE_DIR" ]; then
  echo "ERROR: failed to create baseline snapshot" >&2
  exit 1
fi

# ---------- найти правило ----------
# ipt_NETFLOW обычно сидит в таблице raw, но поищем во всех.
RULE_TABLE=""
RULE_SPEC=""     # то, что пойдёт после "-A PREROUTING": "-i enp5s0d1 -j NETFLOW"
for t in raw mangle nat; do
  lines=$(iptables-save -t "$t" 2>/dev/null | grep -E "^-A PREROUTING .*-j NETFLOW\b" || true)
  if [ -n "$lines" ]; then
    count=$(printf '%s\n' "$lines" | wc -l | awk '{print $1}')
    if (( count > 1 )); then
      echo "ERROR: found $count NETFLOW rules in table $t — refusing to touch:" >&2
      printf '%s\n' "$lines" >&2
      exit 1
    fi
    # совпадает интерфейс?
    if ! printf '%s\n' "$lines" | grep -q -- "-i $IFACE"; then
      echo "WARNING: NETFLOW rule in table $t не относится к $IFACE:" >&2
      printf '%s\n' "$lines" >&2
      continue
    fi
    RULE_TABLE="$t"
    # отрезаем ведущее "-A PREROUTING " — оставляем match+target spec
    RULE_SPEC=$(printf '%s' "$lines" | sed -E 's/^-A PREROUTING //')
    break
  fi
done

if [ -z "$RULE_TABLE" ] || [ -z "$RULE_SPEC" ]; then
  echo "ERROR: no matching NETFLOW rule for $IFACE found in raw/mangle/nat tables" >&2
  exit 1
fi

echo "[$(date +%T)] found rule:"
echo "            table: $RULE_TABLE"
echo "            spec:  PREROUTING $RULE_SPEC"

# ---------- backup iptables ----------
iptables-save > "$IPT_BACKUP"
echo "[$(date +%T)] iptables backup: $IPT_BACKUP ($(wc -l < "$IPT_BACKUP") lines)"

# ---------- убеждаемся, что можем вернуть правило ----------
# используем iptables -C как dry-run — на данном этапе правило ещё на месте
if ! iptables -t "$RULE_TABLE" -C PREROUTING $RULE_SPEC 2>/dev/null; then
  echo "ERROR: iptables -C не подтверждает существование правила — что-то не так" >&2
  exit 1
fi

# ---------- dry-run mode ----------
if (( DRY_RUN )); then
  echo ""
  echo "== DRY RUN =="
  echo "Would execute:"
  echo "  iptables -t $RULE_TABLE -D PREROUTING $RULE_SPEC"
  echo "  (run xdpflowd -iface $IFACE -xdp-action $XDP_ACTION -nf-dst $NF_DSTS for $DURATION s)"
  echo "  iptables -t $RULE_TABLE -I PREROUTING $RULE_SPEC     # restore"
  echo "  (и любой выход/обрыв всё равно вызовет restore через trap)"
  exit 0
fi

# ---------- сохраняем state для panic-restore ----------
cat > "$STATE_FILE" <<EOF
TS=$TS
IFACE=$IFACE
RULE_TABLE=$RULE_TABLE
RULE_SPEC='$RULE_SPEC'
IPT_BACKUP=$IPT_BACKUP
BASELINE_DIR=$BASELINE_DIR
EOF
echo "[$(date +%T)] state saved: $STATE_FILE"

# ---------- сборка ----------
echo "[$(date +%T)] building xdpflowd..."
: "${GO:=go}"
if [ ! -f go.sum ]; then
  echo "[$(date +%T)]   go.sum missing, running 'go mod tidy'..."
  "$GO" mod tidy
fi
make -s >/dev/null
[ -x ./bin/xdpflowd ] || { echo "build failed"; exit 1; }

# ---------- глобальное состояние ----------
XDP_PID=""
SWAP_DONE=0       # 1 = правило уже снято, восстановление обязательно

restore_rule() {
  # идемпотентная функция — можно звать сколько угодно раз
  if (( SWAP_DONE == 0 )); then
    return 0
  fi
  echo "[$(date +%T)] RESTORE: returning iptables rule..."
  local already
  already=$(iptables -t "$RULE_TABLE" -C PREROUTING $RULE_SPEC 2>/dev/null && echo yes || echo no)
  if [[ "$already" == "yes" ]]; then
    echo "[$(date +%T)] RESTORE: rule already in place (nothing to do)"
  else
    # пробуем добавить как было (в начало PREROUTING — ipt_NETFLOW правило
    # обычно раньше любых других; если нет — можно -A).
    if iptables -t "$RULE_TABLE" -I PREROUTING 1 $RULE_SPEC; then
      echo "[$(date +%T)] RESTORE: ok, rule re-inserted into $RULE_TABLE:PREROUTING"
      SWAP_DONE=0
    else
      echo ""
      echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
      echo "!! CRITICAL: failed to restore iptables rule automatically !!"
      echo "!! Manual recovery:                                         !!"
      echo "!!   iptables -t $RULE_TABLE -I PREROUTING 1 $RULE_SPEC"
      echo "!! Or full restore from baseline snapshot:                  !!"
      echo "!!   iptables-restore  < $BASELINE_DIR/10_iptables_save_counters.txt"
      echo "!!   ip6tables-restore < $BASELINE_DIR/10_ip6tables_save_counters.txt"
      echo "!! Or from script backup:                                   !!"
      echo "!!   iptables-restore < $IPT_BACKUP"
      echo "!!   ./scripts/prod_restore.sh $STATE_FILE                  !!"
      echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    fi
  fi
}

run_verify() {
  echo ""
  echo "[$(date +%T)] running verify against baseline $BASELINE_DIR ..."
  if "$REPO_ROOT/scripts/prod_verify.sh" "$BASELINE_DIR" "$IFACE"; then
    echo "[$(date +%T)] VERIFY: state matches baseline."
  else
    echo ""
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!! VERIFY FAILED — production state differs from baseline  !!"
    echo "!! Review above, and if needed run:                        !!"
    echo "!!   iptables-restore  < $BASELINE_DIR/10_iptables_save_counters.txt"
    echo "!!   ip6tables-restore < $BASELINE_DIR/10_ip6tables_save_counters.txt"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  fi
}

cleanup() {
  local rc=$?
  echo ""
  echo "[$(date +%T)] cleanup (exit=$rc)"
  if [ -n "$XDP_PID" ] && kill -0 "$XDP_PID" 2>/dev/null; then
    # Grace: give xdpflowd time to flush the final NFv9 templates +
    # record + NDJSON snapshot for a ~2-3M entry flows map on shutdown.
    # (On prod with XDP_ACTION=drop we measured ~5-10s for flushAll on
    # a 2.5M-flow map; 5s was too tight and led to SIGKILL.)
    kill -TERM "$XDP_PID" 2>/dev/null || true
    for _ in $(seq 1 "$XDP_SHUTDOWN_GRACE"); do
      kill -0 "$XDP_PID" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$XDP_PID" 2>/dev/null; then
      echo "[$(date +%T)] WARN: xdpflowd didn't exit in ${XDP_SHUTDOWN_GRACE}s on SIGTERM — sending SIGKILL"
      kill -KILL "$XDP_PID" 2>/dev/null || true
    fi
  fi
  restore_rule
  # verify только если мы реально заходили в swap
  if [ -n "${BASELINE_DIR:-}" ] && [ -d "$BASELINE_DIR" ]; then
    run_verify || true
  fi
}
# SIGHUP — обрыв SSH. Обязательно ловим.
trap cleanup EXIT INT TERM HUP

# ---------- подготовка памяти для mlx4 native XDP ----------
# mlx4 при attach выделяет contiguous XDP TX rings; на нагруженном проде
# buddy-allocator часто фрагментирован так, что крупные заказы (order>=3)
# падают с ENOMEM. Лечится drop_caches + compact_memory. Делается ДО attach,
# и обязательно ДО удаления ipt_NETFLOW, иначе stall в compact_memory оставит
# интерфейс без старого экспортёра.
prepare_memory() {
  if [[ "$SKIP_MEMORY_PREP" == "1" ]]; then
    echo "[$(date +%T)] memory prep skipped (SKIP_MEMORY_PREP=1)"
    return 0
  fi

  echo "[$(date +%T)] memory prep: drop_caches + compact_memory (timeout ${MEMORY_PREP_TIMEOUT}s)"
  if command -v timeout >/dev/null 2>&1; then
    timeout "${MEMORY_PREP_TIMEOUT}s" bash -c '
      sync
      echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
      echo 1 > /proc/sys/vm/compact_memory 2>/dev/null || true
      sleep 2
    ' || echo "[$(date +%T)] WARN: memory prep timed out or failed; continuing before swap"
  else
    echo "[$(date +%T)] WARN: timeout(1) not found; skipping compact_memory for safety"
  fi

  # краткий отчёт: сколько больших страниц (2048kB / 4096kB) у каждой ноды
  if [[ -r /proc/buddyinfo ]]; then
    awk 'NR<=4 {print "  buddyinfo:",$0}' /proc/buddyinfo
  fi
}
prepare_memory

# ---------- СНИМАЕМ ПРАВИЛО ----------
echo "[$(date +%T)] removing iptables NETFLOW rule..."
iptables -t "$RULE_TABLE" -D PREROUTING $RULE_SPEC
SWAP_DONE=1
echo "[$(date +%T)] rule removed. ipt_NETFLOW no longer seeing packets."

# ---------- запускаем xdpflowd на реальные destination'ы ----------
echo "[$(date +%T)] starting xdpflowd -> $NF_DSTS (xdp-action=$XDP_ACTION)"
if [[ "$XDP_ACTION" == "drop" ]]; then
  echo "[$(date +%T)] WARNING: XDP_DROP — пакеты не дойдут до kernel stack на $IFACE"
fi

# stdbuf: line-buffered stdout/stderr, иначе stats-строки могут ждать в 4KB-буфере
# и не попадать в лог при коротких прогонах.
XDP_STDBUF=""
if command -v stdbuf >/dev/null 2>&1; then
  XDP_STDBUF="stdbuf -oL -eL"
fi

# Продублируем точную командную строку в начало лога, чтобы при разборе
# было видно, с какими флагами реально стартовали.
{
  echo "=== xdpflowd launch at $(date -Is) ==="
  echo "cmdline: $XDP_STDBUF ./bin/xdpflowd -iface $IFACE -mode $XDP_MODE -xdp-action $XDP_ACTION -bpf ./bpf/xdp_flow.o -nf-dst '$NF_DSTS' -nf-active $XDP_NF_ACTIVE -nf-idle $XDP_NF_IDLE -nf-template-interval $XDP_NF_TEMPLATE_INTERVAL -interval 5s -json-out '$JSON_OUT' -json-interval 10s"
  echo "shutdown_grace: ${XDP_SHUTDOWN_GRACE}s"
  echo "WORKDIR: $WORKDIR"
  echo ""
} > "$LOG_XDP"

$XDP_STDBUF ./bin/xdpflowd \
  -iface "$IFACE" \
  -mode "$XDP_MODE" \
  -xdp-action "$XDP_ACTION" \
  -bpf ./bpf/xdp_flow.o \
  -nf-dst "$NF_DSTS" \
  -nf-active "$XDP_NF_ACTIVE" \
  -nf-idle "$XDP_NF_IDLE" \
  -nf-template-interval "$XDP_NF_TEMPLATE_INTERVAL" \
  -interval 5s \
  -json-out "$JSON_OUT" \
  -json-interval 10s \
  >> "$LOG_XDP" 2>&1 &
XDP_PID=$!

# ждём, пока xdpflowd реально прицепит XDP
for i in $(seq 1 15); do
  if grep -q 'xdpflowd started' "$LOG_XDP" 2>/dev/null; then break; fi
  if ! kill -0 "$XDP_PID" 2>/dev/null; then
    echo "ERROR: xdpflowd died during startup!"
    tail -n 40 "$LOG_XDP"
    if grep -q 'cannot allocate memory' "$LOG_XDP" 2>/dev/null; then
      echo ""
      echo "============================================================"
      echo "mlx4 ENOMEM on XDP native attach — память фрагментирована."
      echo ""
      echo "Шаг 1 — подготовить память и повторить:"
      echo "  sync"
      echo "  echo 3 > /proc/sys/vm/drop_caches"
      echo "  timeout 10s bash -c 'echo 1 > /proc/sys/vm/compact_memory'"
      echo "  sleep 3"
      echo "  awk 'NR<=4 {print}' /proc/buddyinfo  # order >=9 не должен быть весь 0"
      echo ""
      echo "Шаг 2 — проверить, не зацепил ли kernel WARN:"
      echo "  dmesg -T | tail -120 | grep -E 'mlx4_en|bpf_xdp_link_release|Failed to allocate NIC'"
      echo "Если виден WARNING bpf_xdp_link_release — драйверный RX path в кривом"
      echo "состоянии и rx_fifo_errors будут расти; ethtool -C/link flap НЕ помогут."
      echo "Полное восстановление:"
      echo "  modprobe -r mlx4_en && modprobe mlx4_en"
      echo "  ip link set $IFACE up"
      echo "  ip link set $IFACE promisc on   # ОБЯЗАТЕЛЬНО, иначе зеркало не вернётся"
      echo "  ethtool -G $IFACE rx 8192"
      echo "  ethtool -C $IFACE adaptive-rx off rx-usecs 512 rx-frames 512"
      echo ""
      echo "Альтернатива — пересобрать xdpflowd с меньшей картой flows (default 4M ≈ 480MB):"
      echo "  make clean && make FLOWS_MAP_SIZE=1000000   # 1M ≈ 120MB"
      echo "============================================================"
    fi
    exit 1
  fi
  sleep 1
done
echo "[$(date +%T)] xdpflowd up (pid=$XDP_PID). log: $LOG_XDP  ndjson: $JSON_OUT"

# sanity: через 15 сек NDJSON должен существовать хотя бы с 1 строкой (-json-interval 10s)
(
  sleep 15
  if kill -0 "$XDP_PID" 2>/dev/null; then
    if [[ ! -s "$JSON_OUT" ]]; then
      echo "[$(date +%T)] WARN: $JSON_OUT пустой через 15с — проверь, что бинарь собран с -json-out" | tee -a "$LOG_XDP"
    else
      lines=$(wc -l < "$JSON_OUT" 2>/dev/null || echo 0)
      echo "[$(date +%T)] ndjson check ok: $lines lines in $JSON_OUT" | tee -a "$LOG_XDP"
    fi
  fi
) &

# ---------- watchdog + main wait ----------
# каждые 10 сек: процесс жив; «живость» = рост любого из
#   total_packets / flows_in_map (msg=stats) — пакеты реально идут в XDP/карту
#   records / packets_out (msg=netflow) — экспорт NFv9 пошёл
# Раньше смотрели только packets_out: при долгом nf-active первые минуты он может
# не расти, хотя total_packets и карта flow уже растут — ложный emergency restore.
echo "[$(date +%T)] running for ${DURATION}s. Ctrl+C to abort early (rule will be restored)."
echo "[$(date +%T)] Watchdog: warmup=${WATCHDOG_WARMUP_SEC}s stall_max=${WATCHDOG_STALL_SEC}s (${WATCHDOG_STALL_INTERVALS}×10s) strict=${WATCHDOG_STRICT}"

xdp_stats_int() {
  # последняя строка msg=stats: total_packets, flows_in_map
  local key=$1
  local line
  line=$(grep 'msg=stats' "$LOG_XDP" 2>/dev/null | tail -1) || { echo 0; return; }
  echo "$line" | grep -oE "${key}=[0-9]+" 2>/dev/null | head -1 | cut -d= -f2 || echo 0
}

xdp_netflow_int() {
  # последняя строка netflow: records, packets_out
  local key=$1
  local line
  line=$(grep 'msg=netflow' "$LOG_XDP" 2>/dev/null | tail -1) || { echo 0; return; }
  echo "$line" | grep -oE "${key}=[0-9]+" 2>/dev/null | head -1 | cut -d= -f2 || echo 0
}

last_tp=0
last_fm=0
last_rec=0
last_po=0
stall_count=0
remaining=$DURATION
while (( remaining > 0 )); do
  sleep 10
  remaining=$(( remaining - 10 ))

  if ! kill -0 "$XDP_PID" 2>/dev/null; then
    echo "[$(date +%T)] WATCHDOG: xdpflowd died. Restoring."
    tail -n 30 "$LOG_XDP"
    exit 1
  fi

  cur_tp=$(xdp_stats_int total_packets)
  cur_fm=$(xdp_stats_int flows_in_map)
  cur_rec=$(xdp_netflow_int records)
  cur_po=$(xdp_netflow_int packets_out)
  cur_tp=${cur_tp:-0}
  cur_fm=${cur_fm:-0}
  cur_rec=${cur_rec:-0}
  cur_po=${cur_po:-0}

  progressed=0
  (( cur_tp > last_tp )) && progressed=1
  (( cur_fm > last_fm )) && progressed=1
  (( cur_rec > last_rec )) && progressed=1
  (( cur_po > last_po )) && progressed=1

  if (( progressed )); then
    stall_count=0
  else
    stall_count=$(( stall_count + 1 ))
  fi
  last_tp=$cur_tp
  last_fm=$cur_fm
  last_rec=$cur_rec
  last_po=$cur_po

  # Долго нет роста ни одного из индикаторов после warmup — мёртвый экспорт или зависание
  if (( stall_count >= WATCHDOG_STALL_INTERVALS )) && (( DURATION - remaining > WATCHDOG_WARMUP_SEC )); then
    echo "[$(date +%T)] WATCHDOG: no progress ${WATCHDOG_STALL_SEC}s (total_packets=$cur_tp flows=$cur_fm records=$cur_rec packets_out=$cur_po)" \
      | tee -a "$LOG_XDP"
    if [[ "$WATCHDOG_STRICT" == "1" ]]; then
      echo "                 Emergency restore (WATCHDOG_STRICT=1)."
      exit 1
    fi
    echo "                 WARN only (WATCHDOG_STRICT=0) — continuing."
    stall_count=0
  fi

  xdp_tail=$(tail -n 1 "$LOG_XDP" 2>/dev/null | tr -d '\n' | cut -c -180)
  echo "[$(date +%T)] +$((DURATION-remaining))s/${DURATION}s  tp=$cur_tp fm=$cur_fm rec=$cur_rec out=$cur_po  $xdp_tail"
done

echo "[$(date +%T)] planned duration reached. Stopping cleanly."
# trap вызовется автоматом на EXIT
