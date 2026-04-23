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
#   7) Watchdog: каждые 10 сек проверяет, что xdpflowd жив И реально шлёт пакеты.
#      Если застрял -> немедленно kill + restore.
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

# Hard cap — нельзя запустить на сутки случайно
MAX_DURATION=3600
if (( DURATION > MAX_DURATION )); then
  echo "ERROR: duration=$DURATION > $MAX_DURATION (hard cap)" >&2
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
need_cmd go
need_cmd clang
need_cmd ss

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
  echo "  (run xdpflowd -iface $IFACE -nf-dst $NF_DSTS for $DURATION s)"
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
    kill -TERM "$XDP_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      kill -0 "$XDP_PID" 2>/dev/null || break
      sleep 1
    done
    kill -KILL "$XDP_PID" 2>/dev/null || true
  fi
  restore_rule
  # verify только если мы реально заходили в swap
  if [ -n "${BASELINE_DIR:-}" ] && [ -d "$BASELINE_DIR" ]; then
    run_verify || true
  fi
}
# SIGHUP — обрыв SSH. Обязательно ловим.
trap cleanup EXIT INT TERM HUP

# ---------- СНИМАЕМ ПРАВИЛО ----------
echo "[$(date +%T)] removing iptables NETFLOW rule..."
iptables -t "$RULE_TABLE" -D PREROUTING $RULE_SPEC
SWAP_DONE=1
echo "[$(date +%T)] rule removed. ipt_NETFLOW no longer seeing packets."

# ---------- запускаем xdpflowd на реальные destination'ы ----------
echo "[$(date +%T)] starting xdpflowd -> $NF_DSTS"
./bin/xdpflowd \
  -iface "$IFACE" \
  -mode native \
  -bpf ./bpf/xdp_flow.o \
  -nf-dst "$NF_DSTS" \
  -nf-active 1800s \
  -nf-idle 15s \
  -nf-template-interval 60s \
  -interval 10s \
  -json-out "$JSON_OUT" \
  -json-interval 30s \
  > "$LOG_XDP" 2>&1 &
XDP_PID=$!

# ждём, пока xdpflowd реально прицепит XDP
for i in $(seq 1 15); do
  if grep -q 'xdpflowd started' "$LOG_XDP" 2>/dev/null; then break; fi
  if ! kill -0 "$XDP_PID" 2>/dev/null; then
    echo "ERROR: xdpflowd died during startup!"
    tail -n 40 "$LOG_XDP"
    exit 1
  fi
  sleep 1
done
echo "[$(date +%T)] xdpflowd up (pid=$XDP_PID). log: $LOG_XDP"

# ---------- watchdog + main wait ----------
# каждые 10 сек проверяем:
#   - процесс жив
#   - в логе ротируется packets_out (т.е. NFv9 реально уходит)
# если застрял 30+ сек без прогресса -> аварийный выход (trap восстановит).
echo "[$(date +%T)] running for ${DURATION}s. Ctrl+C to abort early (rule will be restored)."
last_packets=0
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

  cur_packets=$(grep -oE 'packets_out=[0-9]+' "$LOG_XDP" 2>/dev/null | tail -1 | cut -d= -f2)
  cur_packets=${cur_packets:-0}
  # первые 15 сек нормально иметь 0 — ждём шаблоны и таймауты
  if (( cur_packets > last_packets )); then
    stall_count=0
    last_packets=$cur_packets
  else
    stall_count=$(( stall_count + 1 ))
  fi
  # 30 сек без новых NFv9-пакетов после первой минуты — ненормально
  if (( stall_count >= 3 )) && (( DURATION - remaining > 60 )); then
    echo "[$(date +%T)] WATCHDOG: no NFv9 traffic for 30s (packets_out stuck at $cur_packets)."
    echo "                 Emergency restore."
    exit 1
  fi

  xdp_tail=$(tail -n 1 "$LOG_XDP" 2>/dev/null | tr -d '\n' | cut -c -180)
  echo "[$(date +%T)] +$((DURATION-remaining))s/${DURATION}s  pkts=$cur_packets  $xdp_tail"
done

echo "[$(date +%T)] planned duration reached. Stopping cleanly."
# trap вызовется автоматом на EXIT
