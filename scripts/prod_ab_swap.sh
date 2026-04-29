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
NF_DSTS="${NF_DSTS:-${3:-127.0.0.1:9996,127.0.0.1:9999}}"

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
XDP_CONFIG_FILE="${XDP_CONFIG_FILE:-}"
XDP_CONFIG_ARGS=()
if [[ -n "$XDP_CONFIG_FILE" ]]; then
  if [[ ! -r "$XDP_CONFIG_FILE" ]]; then
    echo "ERROR: XDP_CONFIG_FILE=$XDP_CONFIG_FILE is not readable" >&2
    exit 1
  fi
  XDP_CONFIG_ARGS=( -config "$XDP_CONFIG_FILE" )
fi

# BPF object to load. Default = full flow-tracking program. Override to
# bpf/xdp_light.o to attach the diagnostic "do nothing but bump a counter"
# program — useful for isolating mlx4_en driver/kernel XDP path overhead
# from the cost of bpf/xdp_flow.c. The file must contain a program named
# `xdp_flow_prog` and maps `flows`/`stats` (the loader looks them up by
# name); see bpf/xdp_light.c for a compatible minimal example.
XDP_BPF_OBJ="${XDP_BPF_OBJ:-./bpf/xdp_flow.o}"
if [[ ! -f "$XDP_BPF_OBJ" ]]; then
  echo "ERROR: XDP_BPF_OBJ=$XDP_BPF_OBJ does not exist (run 'make bpf' or 'make bpf-light')" >&2
  exit 1
fi

# Safety: если $IFACE выглядит как обычный роутинг-интерфейс (есть IP/маршруты),
# не даём запустить drop. Исключение — каноничный mirror enp5s0d1.
if [[ "$XDP_ACTION" == "drop" && "$IFACE" != "enp5s0d1" ]]; then
  if ip -4 addr show dev "$IFACE" 2>/dev/null | grep -q 'inet '; then
    echo "ERROR: $IFACE has IPv4 address — refusing XDP_ACTION=drop on non-SPAN interface" >&2
    echo "       drop only supported on enp5s0d1 or pass-through addressless interfaces" >&2
    exit 1
  fi
fi

# Hard cap — нельзя запустить на сутки случайно. Override only for explicit
# long validation runs, e.g. XDP_MAX_DURATION=7200 for a 2h test.
MAX_DURATION="${XDP_MAX_DURATION:-3600}"
if ! [[ "$MAX_DURATION" =~ ^[0-9]+$ ]] || (( MAX_DURATION < 60 )); then
  echo "ERROR: XDP_MAX_DURATION must be integer >= 60" >&2
  exit 1
fi
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
XDP_VERIFY_AFTER="${XDP_VERIFY_AFTER:-1}"
case "$XDP_VERIFY_AFTER" in 0|1) ;; *) echo "ERROR: XDP_VERIFY_AFTER must be 0 or 1" >&2; exit 1;; esac
if ! [[ "$WATCHDOG_STALL_SEC" =~ ^[0-9]+$ ]] || (( WATCHDOG_STALL_SEC < 30 )); then
  echo "ERROR: WATCHDOG_STALL_SEC must be integer >= 30" >&2
  exit 1
fi
WATCHDOG_STALL_INTERVALS=$(( (WATCHDOG_STALL_SEC + 9) / 10 ))

# NetFlow exporter timing (env): shorter active timeout helps short A/B tests
# verify ClickHouse continuity; larger shutdown grace lets final flush finish
# on multi-million flow maps instead of SIGKILL.
# XDP_HEAVY_SERVER=1 — preset for very large flow maps (netflow-class hosts):
#   shorter active/idle, faster map scan, longer shutdown grace. Override any
#   value by exporting XDP_NF_* / XDP_SHUTDOWN_GRACE explicitly before the script.
XDP_HEAVY_SERVER="${XDP_HEAVY_SERVER:-0}"
case "$XDP_HEAVY_SERVER" in 0|1) ;; *) echo "ERROR: XDP_HEAVY_SERVER must be 0 or 1" >&2; exit 1;; esac
if [[ "$XDP_HEAVY_SERVER" == "1" ]]; then
  XDP_NF_ACTIVE="${XDP_NF_ACTIVE:-60s}"
  XDP_NF_IDLE="${XDP_NF_IDLE:-10s}"
  XDP_NF_TEMPLATE_INTERVAL="${XDP_NF_TEMPLATE_INTERVAL:-60s}"
  XDP_NF_SCAN="${XDP_NF_SCAN:-500ms}"
  XDP_SHUTDOWN_GRACE="${XDP_SHUTDOWN_GRACE:-300}"
else
  XDP_NF_ACTIVE="${XDP_NF_ACTIVE:-1800s}"
  XDP_NF_IDLE="${XDP_NF_IDLE:-15s}"
  XDP_NF_TEMPLATE_INTERVAL="${XDP_NF_TEMPLATE_INTERVAL:-60s}"
  XDP_NF_SCAN="${XDP_NF_SCAN:-1s}"
  XDP_SHUTDOWN_GRACE="${XDP_SHUTDOWN_GRACE:-20}"
fi
if ! [[ "$XDP_SHUTDOWN_GRACE" =~ ^[0-9]+$ ]] || (( XDP_SHUTDOWN_GRACE < 20 )); then
  echo "ERROR: XDP_SHUTDOWN_GRACE must be integer >= 20" >&2
  exit 1
fi
XDP_TOP="${XDP_TOP:-0}"
if ! [[ "$XDP_TOP" =~ ^[0-9]+$ ]]; then
  echo "ERROR: XDP_TOP must be a non-negative integer" >&2
  exit 1
fi
XDP_JSON_OUT_ENABLE="${XDP_JSON_OUT_ENABLE:-1}"
XDP_JSON_INTERVAL="${XDP_JSON_INTERVAL:-10s}"
case "$XDP_JSON_OUT_ENABLE" in 0|1) ;; *) echo "ERROR: XDP_JSON_OUT_ENABLE must be 0 or 1" >&2; exit 1;; esac

# Optional local credentials file. Keep it out of git (see .gitignore).
# Default lookup order:
#   1) CH_ENV_FILE=/path/to/file
#   2) ./.clickhouse.env in the repo checkout
#   3) /root/.grapesnta-clickhouse.env
CH_ENV_FILE="${CH_ENV_FILE:-}"
if [[ -z "$CH_ENV_FILE" ]]; then
  if [[ -f ./.clickhouse.env ]]; then
    CH_ENV_FILE="./.clickhouse.env"
  elif [[ -f /root/.grapesnta-clickhouse.env ]]; then
    CH_ENV_FILE="/root/.grapesnta-clickhouse.env"
  fi
fi
PRE_CH_HOST_SET="${CH_HOST+x}"; PRE_CH_HOST="${CH_HOST:-}"
PRE_CH_PORT_SET="${CH_PORT+x}"; PRE_CH_PORT="${CH_PORT:-}"
PRE_CH_USER_SET="${CH_USER+x}"; PRE_CH_USER="${CH_USER:-}"
PRE_CH_PASS_SET="${CH_PASS+x}"; PRE_CH_PASS="${CH_PASS:-}"
PRE_XDP_CH_DSN_SET="${XDP_CH_DSN+x}"; PRE_XDP_CH_DSN="${XDP_CH_DSN:-}"
PRE_XDP_CH_TABLE_SET="${XDP_CH_TABLE+x}"; PRE_XDP_CH_TABLE="${XDP_CH_TABLE:-}"
PRE_XDP_CH_BATCH_SIZE_SET="${XDP_CH_BATCH_SIZE+x}"; PRE_XDP_CH_BATCH_SIZE="${XDP_CH_BATCH_SIZE:-}"
PRE_XDP_CH_FLUSH_INTERVAL_SET="${XDP_CH_FLUSH_INTERVAL+x}"; PRE_XDP_CH_FLUSH_INTERVAL="${XDP_CH_FLUSH_INTERVAL:-}"
PRE_XDP_CH_QUEUE_SIZE_SET="${XDP_CH_QUEUE_SIZE+x}"; PRE_XDP_CH_QUEUE_SIZE="${XDP_CH_QUEUE_SIZE:-}"
PRE_XDP_CH_SAMPLER_ADDR_SET="${XDP_CH_SAMPLER_ADDR+x}"; PRE_XDP_CH_SAMPLER_ADDR="${XDP_CH_SAMPLER_ADDR:-}"
PRE_XDP_CH_SPOOL_MODE_SET="${XDP_CH_SPOOL_MODE+x}"; PRE_XDP_CH_SPOOL_MODE="${XDP_CH_SPOOL_MODE:-}"
PRE_XDP_CH_SPOOL_DIR_SET="${XDP_CH_SPOOL_DIR+x}"; PRE_XDP_CH_SPOOL_DIR="${XDP_CH_SPOOL_DIR:-}"
PRE_XDP_CH_SPOOL_SEGMENT_SIZE_SET="${XDP_CH_SPOOL_SEGMENT_SIZE+x}"; PRE_XDP_CH_SPOOL_SEGMENT_SIZE="${XDP_CH_SPOOL_SEGMENT_SIZE:-}"
PRE_XDP_CH_SPOOL_MAX_BYTES_SET="${XDP_CH_SPOOL_MAX_BYTES+x}"; PRE_XDP_CH_SPOOL_MAX_BYTES="${XDP_CH_SPOOL_MAX_BYTES:-}"
PRE_XDP_CH_SPOOL_FRAME_MAX_RECORDS_SET="${XDP_CH_SPOOL_FRAME_MAX_RECORDS+x}"; PRE_XDP_CH_SPOOL_FRAME_MAX_RECORDS="${XDP_CH_SPOOL_FRAME_MAX_RECORDS:-}"
PRE_XDP_CH_SPOOL_FSYNC_INTERVAL_SET="${XDP_CH_SPOOL_FSYNC_INTERVAL+x}"; PRE_XDP_CH_SPOOL_FSYNC_INTERVAL="${XDP_CH_SPOOL_FSYNC_INTERVAL:-}"
PRE_XDP_CH_SPOOL_SHUTDOWN_DRAIN_SET="${XDP_CH_SPOOL_SHUTDOWN_DRAIN+x}"; PRE_XDP_CH_SPOOL_SHUTDOWN_DRAIN="${XDP_CH_SPOOL_SHUTDOWN_DRAIN:-}"
PRE_XDP_CH_WRITERS_SET="${XDP_CH_WRITERS+x}"; PRE_XDP_CH_WRITERS="${XDP_CH_WRITERS:-}"
if [[ -n "$CH_ENV_FILE" ]]; then
  if [[ ! -r "$CH_ENV_FILE" ]]; then
    echo "ERROR: CH_ENV_FILE=$CH_ENV_FILE is not readable" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  source "$CH_ENV_FILE"
fi
# Explicit sudo/env values win over CH_ENV_FILE. This prevents a credentials file
# from silently redirecting a test back to staging (e.g. XDP_CH_TABLE override).
[[ -n "$PRE_CH_HOST_SET" ]] && CH_HOST="$PRE_CH_HOST"
[[ -n "$PRE_CH_PORT_SET" ]] && CH_PORT="$PRE_CH_PORT"
[[ -n "$PRE_CH_USER_SET" ]] && CH_USER="$PRE_CH_USER"
[[ -n "$PRE_CH_PASS_SET" ]] && CH_PASS="$PRE_CH_PASS"
[[ -n "$PRE_XDP_CH_DSN_SET" ]] && XDP_CH_DSN="$PRE_XDP_CH_DSN"
[[ -n "$PRE_XDP_CH_TABLE_SET" ]] && XDP_CH_TABLE="$PRE_XDP_CH_TABLE"
[[ -n "$PRE_XDP_CH_BATCH_SIZE_SET" ]] && XDP_CH_BATCH_SIZE="$PRE_XDP_CH_BATCH_SIZE"
[[ -n "$PRE_XDP_CH_FLUSH_INTERVAL_SET" ]] && XDP_CH_FLUSH_INTERVAL="$PRE_XDP_CH_FLUSH_INTERVAL"
[[ -n "$PRE_XDP_CH_QUEUE_SIZE_SET" ]] && XDP_CH_QUEUE_SIZE="$PRE_XDP_CH_QUEUE_SIZE"
[[ -n "$PRE_XDP_CH_SAMPLER_ADDR_SET" ]] && XDP_CH_SAMPLER_ADDR="$PRE_XDP_CH_SAMPLER_ADDR"
[[ -n "$PRE_XDP_CH_SPOOL_MODE_SET" ]] && XDP_CH_SPOOL_MODE="$PRE_XDP_CH_SPOOL_MODE"
[[ -n "$PRE_XDP_CH_SPOOL_DIR_SET" ]] && XDP_CH_SPOOL_DIR="$PRE_XDP_CH_SPOOL_DIR"
[[ -n "$PRE_XDP_CH_SPOOL_SEGMENT_SIZE_SET" ]] && XDP_CH_SPOOL_SEGMENT_SIZE="$PRE_XDP_CH_SPOOL_SEGMENT_SIZE"
[[ -n "$PRE_XDP_CH_SPOOL_MAX_BYTES_SET" ]] && XDP_CH_SPOOL_MAX_BYTES="$PRE_XDP_CH_SPOOL_MAX_BYTES"
[[ -n "$PRE_XDP_CH_SPOOL_FRAME_MAX_RECORDS_SET" ]] && XDP_CH_SPOOL_FRAME_MAX_RECORDS="$PRE_XDP_CH_SPOOL_FRAME_MAX_RECORDS"
[[ -n "$PRE_XDP_CH_SPOOL_FSYNC_INTERVAL_SET" ]] && XDP_CH_SPOOL_FSYNC_INTERVAL="$PRE_XDP_CH_SPOOL_FSYNC_INTERVAL"
[[ -n "$PRE_XDP_CH_SPOOL_SHUTDOWN_DRAIN_SET" ]] && XDP_CH_SPOOL_SHUTDOWN_DRAIN="$PRE_XDP_CH_SPOOL_SHUTDOWN_DRAIN"
[[ -n "$PRE_XDP_CH_WRITERS_SET" ]] && XDP_CH_WRITERS="$PRE_XDP_CH_WRITERS"

# Optional direct ClickHouse INSERT from xdpflowd (disabled by default).
# Requires both XDP_CH_DSN and XDP_CH_TABLE; staging DDL: docs/CLICKHOUSE_FLOWS_RAW.md
CH_HOST="${CH_HOST:-95.215.1.30}"
CH_PORT="${CH_PORT:-6124}"
CH_USER="${CH_USER:-develop}"
CH_PASS="${CH_PASS:-}"
XDP_CH_DSN="${XDP_CH_DSN:-}"
XDP_CH_TABLE="${XDP_CH_TABLE:-}"
XDP_CH_BATCH_SIZE="${XDP_CH_BATCH_SIZE:-500}"
XDP_CH_FLUSH_INTERVAL="${XDP_CH_FLUSH_INTERVAL:-1s}"
XDP_CH_QUEUE_SIZE="${XDP_CH_QUEUE_SIZE:-64}"
XDP_CH_SAMPLER_ADDR="${XDP_CH_SAMPLER_ADDR:-}"
XDP_CH_SPOOL_MODE="${XDP_CH_SPOOL_MODE:-}"
XDP_CH_SPOOL_DIR="${XDP_CH_SPOOL_DIR:-}"
XDP_CH_SPOOL_SEGMENT_SIZE="${XDP_CH_SPOOL_SEGMENT_SIZE:-268435456}"
XDP_CH_SPOOL_MAX_BYTES="${XDP_CH_SPOOL_MAX_BYTES:-0}"
XDP_CH_SPOOL_FRAME_MAX_RECORDS="${XDP_CH_SPOOL_FRAME_MAX_RECORDS:-50000}"
XDP_CH_SPOOL_FSYNC_INTERVAL="${XDP_CH_SPOOL_FSYNC_INTERVAL:-1s}"
XDP_CH_SPOOL_SHUTDOWN_DRAIN="${XDP_CH_SPOOL_SHUTDOWN_DRAIN:-0s}"
XDP_CH_WRITERS="${XDP_CH_WRITERS:-4}"
case "${XDP_CH_SPOOL_MODE:-off}" in
  off|on|required) ;;
  *) echo "ERROR: XDP_CH_SPOOL_MODE must be off|on|required (got: $XDP_CH_SPOOL_MODE)" >&2; exit 1;;
esac
CH_EXTRA_ARGS=()
if [[ -z "$XDP_CH_DSN" && -n "$XDP_CH_TABLE" && -n "$CH_PASS" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    CH_PASS_URL="$(CH_PASS="$CH_PASS" python3 -c 'import os, urllib.parse; print(urllib.parse.quote(os.environ["CH_PASS"], safe=""))')"
    XDP_CH_DSN="clickhouse://${CH_USER}:${CH_PASS_URL}@${CH_HOST}:${CH_PORT}/default"
  else
    echo "ERROR: python3 is required to URL-encode CH_PASS into XDP_CH_DSN; set XDP_CH_DSN explicitly" >&2
    exit 1
  fi
fi
if [[ -n "$XDP_CH_DSN" || -n "$XDP_CH_TABLE" ]]; then
  if [[ -z "$XDP_CH_DSN" || -z "$XDP_CH_TABLE" ]]; then
    echo "ERROR: set both XDP_CH_DSN and XDP_CH_TABLE for ClickHouse direct ingest, or set CH_PASS plus XDP_CH_TABLE" >&2
    exit 1
  fi
  CH_EXTRA_ARGS=(
    -ch-dsn "$XDP_CH_DSN"
    -ch-table "$XDP_CH_TABLE"
    -ch-batch-size "$XDP_CH_BATCH_SIZE"
    -ch-flush-interval "$XDP_CH_FLUSH_INTERVAL"
    -ch-queue-size "$XDP_CH_QUEUE_SIZE"
  )
  if [[ -n "$XDP_CH_SAMPLER_ADDR" ]]; then
    CH_EXTRA_ARGS+=( -ch-sampler-addr "$XDP_CH_SAMPLER_ADDR" )
  fi
  if [[ -n "$XDP_CH_SPOOL_DIR" ]]; then
    CH_EXTRA_ARGS+=(
      -ch-spool-mode "${XDP_CH_SPOOL_MODE:-on}"
      -ch-spool-dir "$XDP_CH_SPOOL_DIR"
      -ch-spool-segment-size "$XDP_CH_SPOOL_SEGMENT_SIZE"
      -ch-spool-max-bytes "$XDP_CH_SPOOL_MAX_BYTES"
      -ch-spool-frame-max-records "$XDP_CH_SPOOL_FRAME_MAX_RECORDS"
      -ch-spool-fsync-interval "$XDP_CH_SPOOL_FSYNC_INTERVAL"
      -ch-spool-shutdown-drain "$XDP_CH_SPOOL_SHUTDOWN_DRAIN"
      -ch-writers "$XDP_CH_WRITERS"
    )
  elif [[ "${XDP_CH_SPOOL_MODE:-off}" != "off" ]]; then
    echo "ERROR: XDP_CH_SPOOL_MODE=$XDP_CH_SPOOL_MODE requires XDP_CH_SPOOL_DIR" >&2
    exit 1
  fi
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
JSON_ARGS=()
JSON_LABEL="disabled"
if [[ "$XDP_JSON_OUT_ENABLE" == "1" ]]; then
  JSON_ARGS=( -json-out "$JSON_OUT" -json-interval "$XDP_JSON_INTERVAL" )
  JSON_LABEL="$JSON_OUT"
fi

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

emit_final_xdp_log() {
  if [[ ! -s "$LOG_XDP" ]]; then
    return 0
  fi
  echo ""
  echo "[$(date +%T)] final xdpflowd delivery/shutdown log lines:"
  grep -E 'clickhouse spool shutdown drain complete|clickhouse spool pipeline closed|records_spooled|records_acked|insert_errs|retries|caught_up|spool cleanup removed|shutdown|ERROR|WARN' \
    "$LOG_XDP" | tail -80 || true
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
  emit_final_xdp_log
  restore_rule
  # verify только если мы реально заходили в swap
  if [[ "$XDP_VERIFY_AFTER" == "1" && -n "${BASELINE_DIR:-}" && -d "$BASELINE_DIR" ]]; then
    run_verify || true
  elif [[ "$XDP_VERIFY_AFTER" != "1" ]]; then
    echo "[$(date +%T)] VERIFY: skipped by XDP_VERIFY_AFTER=0"
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
  echo "cmdline: $XDP_STDBUF ./bin/xdpflowd ${XDP_CONFIG_ARGS[*]} -iface $IFACE -mode $XDP_MODE -xdp-action $XDP_ACTION -bpf $XDP_BPF_OBJ -nf-dst '$NF_DSTS' -nf-active $XDP_NF_ACTIVE -nf-idle $XDP_NF_IDLE -nf-template-interval $XDP_NF_TEMPLATE_INTERVAL -nf-scan $XDP_NF_SCAN -top $XDP_TOP -interval 5s ${JSON_ARGS[*]} ${CH_EXTRA_ARGS[*]}"
  echo "shutdown_grace: ${XDP_SHUTDOWN_GRACE}s"
  echo "WORKDIR: $WORKDIR"
  echo ""
} > "$LOG_XDP"

$XDP_STDBUF ./bin/xdpflowd \
  "${XDP_CONFIG_ARGS[@]}" \
  -iface "$IFACE" \
  -mode "$XDP_MODE" \
  -xdp-action "$XDP_ACTION" \
  -bpf "$XDP_BPF_OBJ" \
  -nf-dst "$NF_DSTS" \
  -nf-active "$XDP_NF_ACTIVE" \
  -nf-idle "$XDP_NF_IDLE" \
  -nf-template-interval "$XDP_NF_TEMPLATE_INTERVAL" \
  -nf-scan "$XDP_NF_SCAN" \
  -top "$XDP_TOP" \
  -interval 5s \
  "${JSON_ARGS[@]}" \
  "${CH_EXTRA_ARGS[@]}" \
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
echo "[$(date +%T)] xdpflowd up (pid=$XDP_PID). log: $LOG_XDP  ndjson: $JSON_LABEL"

# sanity: через 15 сек NDJSON должен существовать хотя бы с 1 строкой (-json-interval 10s)
if [[ "$XDP_JSON_OUT_ENABLE" == "1" ]]; then
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
fi

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
