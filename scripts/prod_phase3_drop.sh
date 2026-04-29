#!/usr/bin/env bash
# prod_phase3_drop.sh — ОДИН запуск, 3 замера CPU, диагностика + XDP_DROP swap.
#
# Что делает по шагам:
#   1) Sanity checks, собирает baseline snapshot (iptables/sysctl/модули/NIC).
#   2) Показывает текущую картину IRQ: сколько очередей, какой CPU горит.
#   3) Запрашивает подтверждение: раскидать ли IRQ по CPU?
#        - если yes: сохраняет старую привязку, раскидывает круговым способом.
#   4) ЗАМЕР A: "как было / как стало после IRQ spread". mpstat 30s.
#   5) Запускает prod_ab_swap.sh с XDP_ACTION=drop в фоне.
#   6) ЗАМЕР B: xdpflowd в режиме DROP. mpstat + bpftool profile + /proc/interrupts.
#   7) prod_ab_swap сам восстанавливает iptables по истечению времени или обрыву.
#   8) Оркестратор восстанавливает IRQ affinity + перезапускает irqbalance.
#   9) Печатает сравнительный отчёт A vs B.
#
# Использование:
#   sudo ./scripts/prod_phase3_drop.sh [duration_sec] [iface]
#
# Параметры (env):
#   DURATION_DROP — сколько секунд держать xdpflowd в DROP (default 120)
#   DURATION_WINDOW — окно измерения mpstat (default 30)
#   SKIP_IRQ_TUNE=1 — не предлагать IRQ spread (только замерить drop)
#   AUTO_IRQ=1 — раскинуть IRQ без интерактивного вопроса
#   CPU_LIST="4,5,6,7,8,9,10,11" — список CPU для IRQ spread
#   XDP_MODE=native|generic — default native
#   CH_PASS=... — опционально: снять ClickHouse rows/packets/bytes
#       за последние CH_LOOKBACK_MIN минут до swap и после swap (default 2).
#       По умолчанию БД захардкожена под текущий прод: default.flows_raw @ 95.215.1.30:6124.
#       Настройки: CH_HOST, CH_PORT, CH_USER, CH_TIME_EXPR, CH_PACKETS_COL, CH_BYTES_COL.
#   Прямой INSERT из xdpflowd в staging (опционально): задайте оба XDP_CH_DSN и XDP_CH_TABLE
#       (см. docs/CLICKHOUSE_FLOWS_RAW.md). Передаются в prod_ab_swap.sh как есть.
#   XDP_HEAVY_SERVER=1 — preset для очень больших карт flow (см. prod_ab_swap.sh).
#   Durable spool: XDP_CH_SPOOL_DIR и опционально XDP_CH_SPOOL_MODE / XDP_CH_WRITERS
#       (см. docs/CLICKHOUSE_FLOWS_RAW.md и docs/FLOW_STORAGE_CONTRACTS.md).
#   XDP_STOP_GOFLOW2=1 — на время swap остановить контейнеры goflow2, чтобы они
#       не влияли на CPU. Список: XDP_GOFLOW2_CONTAINERS="kcg-goflow2-1".

set -euo pipefail

DURATION_DROP="${DURATION_DROP:-${1:-120}}"
IFACE="${2:-enp5s0d1}"
DURATION_WINDOW="${DURATION_WINDOW:-30}"
SKIP_IRQ_TUNE="${SKIP_IRQ_TUNE:-0}"
AUTO_IRQ="${AUTO_IRQ:-0}"
CPU_LIST="${CPU_LIST:-}"
XDP_MODE="${XDP_MODE:-native}"
# XDP_ACTION: drop (default, full replacement test) or pass (diagnostic —
# BPF runs but packets still go up the kernel stack, useful for isolating
# "BPF program is slow" vs "XDP infrastructure adds mlx4 overhead").
XDP_ACTION="${XDP_ACTION:-drop}"
case "$XDP_ACTION" in pass|drop) ;; *) echo "ERROR: XDP_ACTION must be pass|drop"; exit 1;; esac

# BPF object passed through to prod_ab_swap.sh. Override to bpf/xdp_light.o
# to attach the diagnostic minimal program (counter only, no parsing) and
# isolate mlx4_en native XDP path overhead from the cost of the real
# flow-tracking program. Empty string = let prod_ab_swap.sh use its default.
XDP_BPF_OBJ="${XDP_BPF_OBJ:-}"
XDP_TOP="${XDP_TOP:-0}"
XDP_JSON_OUT_ENABLE="${XDP_JSON_OUT_ENABLE:-1}"
XDP_JSON_INTERVAL="${XDP_JSON_INTERVAL:-10s}"

# NetFlow destinations for xdpflowd. Default preserves the current production
# fanout: local nfcapd plus goflow2. For direct-ClickHouse CPU tests, set
# NF_DSTS=127.0.0.1:9996 to keep local capture while removing goflow2 from
# the hot path.
NF_DSTS="${NF_DSTS:-127.0.0.1:9996,127.0.0.1:9999}"
XDP_STOP_GOFLOW2="${XDP_STOP_GOFLOW2:-0}"
XDP_GOFLOW2_CONTAINERS="${XDP_GOFLOW2_CONTAINERS:-kcg-goflow2-1}"
case "$XDP_STOP_GOFLOW2" in 0|1) ;; *) echo "ERROR: XDP_STOP_GOFLOW2 must be 0 or 1" >&2; exit 1;; esac

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
PRE_CH_TABLE_SET="${CH_TABLE+x}"; PRE_CH_TABLE="${CH_TABLE:-}"
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
# Explicit sudo/env values win over CH_ENV_FILE. Keep this in sync with
# prod_ab_swap.sh so test wrappers cannot be silently redirected by env files.
[[ -n "$PRE_CH_HOST_SET" ]] && CH_HOST="$PRE_CH_HOST"
[[ -n "$PRE_CH_PORT_SET" ]] && CH_PORT="$PRE_CH_PORT"
[[ -n "$PRE_CH_USER_SET" ]] && CH_USER="$PRE_CH_USER"
[[ -n "$PRE_CH_PASS_SET" ]] && CH_PASS="$PRE_CH_PASS"
[[ -n "$PRE_CH_TABLE_SET" ]] && CH_TABLE="$PRE_CH_TABLE"
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

CH_HOST="${CH_HOST:-95.215.1.30}"
CH_PORT="${CH_PORT:-6124}"
CH_USER="${CH_USER:-develop}"
CH_PASS="${CH_PASS:-}"
# Prod defaults (можно переопределить env'ами при необходимости)
CH_TABLE="${CH_TABLE:-default.flows_raw}"
# default.flows — Kafka engine, читать надо materialized storage default.flows_raw.
# time_received_ns там уже DateTime64(9), без epoch-конвертации.
CH_TIME_EXPR="${CH_TIME_EXPR:-time_received_ns}"
CH_PACKETS_COL="${CH_PACKETS_COL:-packets}"
CH_BYTES_COL="${CH_BYTES_COL:-bytes}"
CH_LOOKBACK_MIN="${CH_LOOKBACK_MIN:-2}"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TS="$(date +%Y%m%d_%H%M%S)"
WORKDIR="/tmp/phase3_${XDP_ACTION}_$TS"
mkdir -p "$WORKDIR"

A_DIR="$WORKDIR/A_baseline"                   # замер A: без xdpflowd
B_DIR="$WORKDIR/B_xdp${XDP_ACTION}"           # замер B: xdpflowd активен
mkdir -p "$A_DIR" "$B_DIR"

LOG="$WORKDIR/orchestrator.log"
SUMMARY="$WORKDIR/SUMMARY.txt"

exec > >(tee -a "$LOG") 2>&1

echo "======================================================================"
echo "Phase 3 ${XDP_ACTION^^} test — $TS"
echo "iface=$IFACE  xdp-mode=$XDP_MODE  xdp-action=$XDP_ACTION  duration=${DURATION_DROP}s  bpf=${XDP_BPF_OBJ:-default}"
echo "workdir=$WORKDIR"
echo "======================================================================"

# ---------- проверки ----------
# Обязательные — без них тест не выполнить
for c in mpstat ethtool ip; do
  command -v "$c" >/dev/null || { echo "ERROR: missing $c (apt install sysstat ethtool iproute2)"; exit 1; }
done
# Опциональные — просто уменьшают детализацию отчёта
HAVE_BPFTOOL=0
HAVE_PERF=0
HAVE_CH=0
command -v bpftool >/dev/null && HAVE_BPFTOOL=1 || \
  echo "NOTE: bpftool not installed — cycles/packet metric will be skipped (try: apt install bpftool or linux-perf)"
command -v perf >/dev/null && HAVE_PERF=1 || \
  echo "NOTE: perf not installed — top kernel functions will be skipped (try: apt install linux-perf)"
if command -v clickhouse-client >/dev/null 2>&1 && [[ -n "$CH_PASS" && -n "$CH_TABLE" ]]; then
  HAVE_CH=1
  echo "ClickHouse check enabled: ${CH_TABLE} @ ${CH_HOST}:${CH_PORT}, lookback=${CH_LOOKBACK_MIN}m"
else
  echo "NOTE: ClickHouse check disabled — set CH_PASS and CH_TABLE=db.table to compare DB rows before/after swap"
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "ERROR: interface $IFACE not found"; exit 1
fi

if [[ ! -x ./bin/xdpflowd ]]; then
  echo "ERROR: ./bin/xdpflowd not built. Run: make clean && make"; exit 1
fi
if [[ ! -f ./bpf/xdp_flow.o ]]; then
  echo "ERROR: ./bpf/xdp_flow.o missing. Run: make"; exit 1
fi

# ---------- сбор окна измерения ----------
# Одно окно = mpstat $DURATION_WINDOW сек + snapshot /proc/interrupts до/после
# + perf top 10 сек на горячем CPU (если perf есть) + bpftool prog profile (опц.)
collect_window() {
  local name=$1        # A | B
  local dir=$2
  local with_prog=${3:-0}   # 1 если во время xdpflowd — собирать bpftool profile

  local dur=$DURATION_WINDOW

  echo ""
  echo "[WINDOW $name] starting — ${dur}s mpstat, interrupts, (perf if available)..."

  cp /proc/interrupts "$dir/interrupts.before"

  # NIC drop-rate: снимаем ДО и ПОСЛЕ, в конце получаем дельту за окно.
  # sysfs counter не сбрасывается между выборками (в отличие от ethtool после
  # XDP attach), поэтому дельта точно отражает "потери за это окно".
  cat /sys/class/net/"$IFACE"/statistics/rx_fifo_errors \
    > "$dir/rx_fifo_errors.before" 2>/dev/null || echo 0 > "$dir/rx_fifo_errors.before"
  cat /sys/class/net/"$IFACE"/statistics/rx_packets \
    > "$dir/rx_packets.before" 2>/dev/null || echo 0 > "$dir/rx_packets.before"
  cat /sys/class/net/"$IFACE"/statistics/rx_bytes \
    > "$dir/rx_bytes.before" 2>/dev/null || echo 0 > "$dir/rx_bytes.before"

  # mpstat — фон, записывает в файл
  mpstat -P ALL 5 "$((dur / 5))" > "$dir/mpstat.txt" 2>&1 &
  MPSTAT_PID=$!

  # perf top на 10 сек если есть
  if (( HAVE_PERF == 1 )); then
    (
      # найти "горячий" CPU по текущему softirq (топ из top)
      HOT_CPU=$(mpstat -P ALL 1 1 2>/dev/null \
                | awk '$3 ~ /^[0-9]+$/ {print $NF,$3}' \
                | sort -rn | head -1 | awk '{print $2}')
      HOT_CPU=${HOT_CPU:-0}
      echo "[WINDOW $name] perf top -C $HOT_CPU for 10s" >&2
      timeout 10 perf top -C "$HOT_CPU" --no-children -g -E 20 2>/dev/null \
        > "$dir/perf_top.txt" || true
    ) &
  fi

  # bpftool prog profile (только в окне B — когда xdpflowd живой)
  if (( with_prog == 1 && HAVE_BPFTOOL == 1 )); then
    (
      # найти программу xdp_flow_prog
      local pid=""
      for i in 1 2 3 4 5; do
        pid=$(bpftool prog show 2>/dev/null | awk '/xdp_flow_prog/{gsub(":","",$1); print $1; exit}')
        [[ -n "$pid" ]] && break
        sleep 1
      done
      if [[ -n "$pid" ]]; then
        echo "[WINDOW $name] bpftool profile id $pid for 10s" >&2
        timeout 10 bpftool prog profile id "$pid" duration 10 cycles instructions \
          > "$dir/bpftool_profile.txt" 2>&1 || true
      else
        echo "no xdp_flow_prog found via bpftool" > "$dir/bpftool_profile.txt"
      fi
    ) &
  fi

  # wait mpstat
  wait "$MPSTAT_PID" || true

  cp /proc/interrupts "$dir/interrupts.after"

  # delta-snapshot NIC
  cat /sys/class/net/"$IFACE"/statistics/rx_fifo_errors \
    > "$dir/rx_fifo_errors.after" 2>/dev/null || echo 0 > "$dir/rx_fifo_errors.after"
  cat /sys/class/net/"$IFACE"/statistics/rx_packets \
    > "$dir/rx_packets.after" 2>/dev/null || echo 0 > "$dir/rx_packets.after"
  cat /sys/class/net/"$IFACE"/statistics/rx_bytes \
    > "$dir/rx_bytes.after" 2>/dev/null || echo 0 > "$dir/rx_bytes.after"

  # сохранить NIC counters
  ip -s link show "$IFACE" > "$dir/ip_s_link.txt" 2>&1 || true
  ethtool -S "$IFACE" > "$dir/ethtool_S.txt" 2>&1 || true

  echo "[WINDOW $name] done."
}

collect_clickhouse_window() {
  local label=$1
  local out=$2
  if (( HAVE_CH != 1 )); then
    return 0
  fi

  echo ""
  echo "[CLICKHOUSE $label] last ${CH_LOOKBACK_MIN} minute(s) from ${CH_TABLE}..."
  {
    echo "label=$label"
    echo "captured_at=$(date -Is)"
    echo "host=$CH_HOST port=$CH_PORT table=$CH_TABLE"
    echo "time_expr=$CH_TIME_EXPR packets_col=$CH_PACKETS_COL bytes_col=$CH_BYTES_COL lookback_min=$CH_LOOKBACK_MIN"
    echo ""
    echo "-- per-minute rows/packets/bytes --"
    clickhouse-client --host "$CH_HOST" --port "$CH_PORT" -u "$CH_USER" --password "$CH_PASS" --format PrettyCompact -q "
      SELECT
        toStartOfMinute(${CH_TIME_EXPR}) AS minute,
        count() AS rows,
        sum(${CH_PACKETS_COL}) AS packets,
        sum(${CH_BYTES_COL}) AS bytes
      FROM ${CH_TABLE}
      WHERE ${CH_TIME_EXPR} >= now() - INTERVAL ${CH_LOOKBACK_MIN} MINUTE
      GROUP BY minute
      ORDER BY minute
    "
    echo ""
    echo "-- totals --"
    clickhouse-client --host "$CH_HOST" --port "$CH_PORT" -u "$CH_USER" --password "$CH_PASS" --format PrettyCompact -q "
      SELECT
        count() AS rows,
        sum(${CH_PACKETS_COL}) AS packets,
        sum(${CH_BYTES_COL}) AS bytes,
        toString(min(${CH_TIME_EXPR})) AS min_ts,
        toString(max(${CH_TIME_EXPR})) AS max_ts
      FROM ${CH_TABLE}
      WHERE ${CH_TIME_EXPR} >= now() - INTERVAL ${CH_LOOKBACK_MIN} MINUTE
    "
  } > "$out" 2>&1 || {
    echo "[CLICKHOUSE $label] query failed, see $out"
    return 0
  }
  sed -n '1,40p' "$out"
}

# ---------- 1) Snapshot ----------
if [[ -x "$REPO_ROOT/scripts/prod_snapshot.sh" ]]; then
  "$REPO_ROOT/scripts/prod_snapshot.sh" "$IFACE" > "$WORKDIR/snapshot.log" 2>&1 || true
fi

# ---------- 2) IRQ state ----------
echo ""
echo "== IRQ state BEFORE =="
"$REPO_ROOT/scripts/prod_tune_irq.sh" show "$IFACE" | tee "$WORKDIR/irq_before.txt" || true

# ---------- 3) IRQ spread? ----------
IRQ_SPREAD_APPLIED=0
GOFLOW2_STOPPED=()
if [[ "$SKIP_IRQ_TUNE" != "1" ]]; then
  if [[ "$AUTO_IRQ" == "1" ]]; then
    ans=y
  else
    echo ""
    echo -n "Раскидать IRQ $IFACE по CPU перед тестом? [y/N] "
    read -r ans < /dev/tty || ans=n
  fi
  if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
    "$REPO_ROOT/scripts/prod_tune_irq.sh" spread "$IFACE" "$CPU_LIST" \
      | tee "$WORKDIR/irq_spread.log"
    IRQ_SPREAD_APPLIED=1
    echo ""
    echo "== IRQ state AFTER SPREAD =="
    "$REPO_ROOT/scripts/prod_tune_irq.sh" show "$IFACE" | tee "$WORKDIR/irq_after_spread.txt"
    echo ""
    echo "Ждём 5 сек чтобы новая affinity устаканилась..."
    sleep 5
  fi
fi

# ---------- trap: всегда откатить IRQ ----------
cleanup() {
  local rc=$?
  echo ""
  echo "== CLEANUP (rc=$rc) =="
  if (( ${#GOFLOW2_STOPPED[@]} > 0 )); then
    echo "== START goflow2 containers =="
    for c in "${GOFLOW2_STOPPED[@]}"; do
      echo "starting $c ..."
      docker start "$c" >/dev/null || echo "WARN: failed to start $c" >&2
      if [[ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null || echo false)" == "true" ]]; then
        echo "$c running"
      else
        echo "WARN: $c is not running after start" >&2
      fi
    done | tee "$WORKDIR/goflow2_restart.log"
  fi
  if (( IRQ_SPREAD_APPLIED == 1 )); then
    "$REPO_ROOT/scripts/prod_tune_irq.sh" restore "$IFACE" \
      | tee "$WORKDIR/irq_restore.log" || true
  fi
  # prod_ab_swap имеет свой trap на iptables — он сам вернёт правило.
  echo "Results saved to: $WORKDIR"
  if [[ -f "$SUMMARY" ]]; then
    echo ""
    echo "===== SUMMARY ====="
    cat "$SUMMARY"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM HUP

# ---------- 4) ЗАМЕР A ----------
echo ""
echo "===== WINDOW A: baseline (no xdpflowd), after IRQ tune ====="
collect_window A "$A_DIR" 0

collect_clickhouse_window "BEFORE_SWITCH_${CH_LOOKBACK_MIN}MIN" "$WORKDIR/clickhouse_before_switch.txt"

# ---------- Optional: stop goflow2 during replacement window ----------
if [[ "$XDP_STOP_GOFLOW2" == "1" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: XDP_STOP_GOFLOW2=1 but docker is not available" >&2
    exit 1
  fi
  echo ""
  echo "===== Stopping goflow2 containers for XDP test ====="
  for c in $XDP_GOFLOW2_CONTAINERS; do
    if ! docker inspect "$c" >/dev/null 2>&1; then
      echo "WARN: container $c not found"
      continue
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$c")" == "true" ]]; then
      GOFLOW2_STOPPED+=("$c")
      docker stop "$c" | tee -a "$WORKDIR/goflow2_stop.log"
    else
      echo "container $c already stopped" | tee -a "$WORKDIR/goflow2_stop.log"
    fi
  done
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
    | grep -E 'goflow|NAME' | tee "$WORKDIR/goflow2_after_stop.txt" || true
fi

# ---------- 5) Запуск prod_ab_swap с заданным XDP_ACTION в фоне ----------
echo ""
echo "===== Starting prod_ab_swap (XDP_ACTION=$XDP_ACTION, ${DURATION_DROP}s) ====="
cat /sys/class/net/"$IFACE"/statistics/rx_fifo_errors \
  > "$WORKDIR/rx_fifo_errors.full_before" 2>/dev/null || echo 0 > "$WORKDIR/rx_fifo_errors.full_before"
(
  XDP_ACTION="$XDP_ACTION" \
  XDP_MODE="$XDP_MODE" \
  XDP_BPF_OBJ="$XDP_BPF_OBJ" \
  NF_DSTS="$NF_DSTS" \
  XDP_CH_DSN="${XDP_CH_DSN:-}" \
  XDP_CH_TABLE="${XDP_CH_TABLE:-}" \
  XDP_CH_BATCH_SIZE="${XDP_CH_BATCH_SIZE:-500}" \
  XDP_CH_FLUSH_INTERVAL="${XDP_CH_FLUSH_INTERVAL:-1s}" \
  XDP_CH_QUEUE_SIZE="${XDP_CH_QUEUE_SIZE:-64}" \
  XDP_CH_SAMPLER_ADDR="${XDP_CH_SAMPLER_ADDR:-}" \
  XDP_CH_SPOOL_MODE="${XDP_CH_SPOOL_MODE:-}" \
  XDP_CH_SPOOL_DIR="${XDP_CH_SPOOL_DIR:-}" \
  XDP_CH_SPOOL_SEGMENT_SIZE="${XDP_CH_SPOOL_SEGMENT_SIZE:-268435456}" \
  XDP_CH_SPOOL_MAX_BYTES="${XDP_CH_SPOOL_MAX_BYTES:-0}" \
  XDP_CH_SPOOL_FRAME_MAX_RECORDS="${XDP_CH_SPOOL_FRAME_MAX_RECORDS:-50000}" \
  XDP_CH_SPOOL_FSYNC_INTERVAL="${XDP_CH_SPOOL_FSYNC_INTERVAL:-1s}" \
  XDP_CH_SPOOL_SHUTDOWN_DRAIN="${XDP_CH_SPOOL_SHUTDOWN_DRAIN:-0s}" \
  XDP_CH_WRITERS="${XDP_CH_WRITERS:-4}" \
  XDP_TOP="$XDP_TOP" \
  XDP_JSON_OUT_ENABLE="$XDP_JSON_OUT_ENABLE" \
  XDP_JSON_INTERVAL="$XDP_JSON_INTERVAL" \
    "$REPO_ROOT/scripts/prod_ab_swap.sh" \
    "$DURATION_DROP" "$IFACE" \
    > "$WORKDIR/prod_ab_swap.log" 2>&1
) &
SWAP_PID=$!

# ---------- ждём, пока xdpflowd реально поднимется ----------
echo "Waiting for xdpflowd to start (up to 30s)..."
for i in $(seq 1 30); do
  if grep -q "xdpflowd up" "$WORKDIR/prod_ab_swap.log" 2>/dev/null; then
    echo "xdpflowd up."
    break
  fi
  if ! kill -0 "$SWAP_PID" 2>/dev/null; then
    echo "ERROR: prod_ab_swap died before xdpflowd came up"
    tail -n 30 "$WORKDIR/prod_ab_swap.log"
    exit 1
  fi
  sleep 1
done

# Доп. 5 сек на стабилизацию (шаблоны NFv9, flows заполняются)
sleep 5

# ---------- 6) ЗАМЕР B ----------
echo ""
echo "===== WINDOW B: xdpflowd XDP_${XDP_ACTION^^} ====="
collect_window B "$B_DIR" 1

# ---------- 7) дождаться окончания swap ----------
echo ""
echo "Waiting for prod_ab_swap to finish..."
wait "$SWAP_PID" || true
cat /sys/class/net/"$IFACE"/statistics/rx_fifo_errors \
  > "$WORKDIR/rx_fifo_errors.full_after" 2>/dev/null || echo 0 > "$WORKDIR/rx_fifo_errors.full_after"

echo ""
echo "===== POST-TEST fifo_drops check (3x10s) ====="
for i in 1 2 3; do
  before=$(cat /sys/class/net/"$IFACE"/statistics/rx_fifo_errors 2>/dev/null || echo 0)
  sleep 10
  after=$(cat /sys/class/net/"$IFACE"/statistics/rx_fifo_errors 2>/dev/null || echo 0)
  delta=$((after - before))
  echo "$(date +%T) post-test fifo/10s = $delta" | tee -a "$WORKDIR/rx_fifo_errors.post_test.txt"
done

collect_clickhouse_window "AFTER_SWITCH_${CH_LOOKBACK_MIN}MIN" "$WORKDIR/clickhouse_after_switch.txt"

# ---------- 8) сравнительный отчёт ----------
echo ""
echo "===== BUILDING SUMMARY ====="

summarize_mpstat() {
  local f=$1
  # mpstat columns (after "Average:" and CPU-id):
  #   $3=%usr $4=%nice $5=%sys $6=%iowait $7=%irq $8=%soft $9=%steal
  #   $10=%guest $11=%gnice $12=%idle ($NF on modern sysstat)
  awk '
    /^Average:/ && $2=="all" {
      printf "  all: usr=%s sys=%s soft=%s idle=%s\n", $3, $5, $8, $NF; next
    }
    /^Average:/ && $2 ~ /^[0-9]+$/ {
      soft=$8
      if (soft+0 > 5) printf "  CPU %s: softirq=%s%% idle=%s%%\n", $2, soft, $NF
    }
  ' "$f"
}

interrupts_delta_per_cpu() {
  local before=$1 after=$2 iface=$3

  # Определяем, по какому "маркеру" искать IRQ в /proc/interrupts:
  # у mlx4 имя IRQ выглядит "mlx4-25@0000:05:00.0" — там PCI-id, а не iface.
  # Поэтому ищем одновременно iface И pci, берём объединение совпадений.
  local pci=""
  if [[ -L "/sys/class/net/${iface}/device" ]]; then
    pci=$(basename "$(readlink -f /sys/class/net/"$iface"/device)")
  fi

  python3 - "$before" "$after" "$iface" "$pci" <<'PY' 2>/dev/null || return 0
import sys, re
before, after, iface, pci = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
def parse(f):
    out = {}
    with open(f) as fh:
        for line in fh:
            m = re.match(r'^\s*(\S+):\s+(.*)$', line.rstrip('\n'))
            if not m: continue
            irq, rest = m.group(1), m.group(2)
            parts = rest.split()
            counts = []
            name = ''
            for i,p in enumerate(parts):
                if p.isdigit():
                    counts.append(int(p))
                else:
                    name = ' '.join(parts[i:])
                    break
            # match by iface name or PCI id anywhere in the IRQ description
            matched = False
            if iface and iface in name: matched = True
            if pci and pci in name: matched = True
            if matched:
                out[irq] = counts
    return out
a = parse(before); b = parse(after)
irqs = sorted(set(a) | set(b), key=lambda s: int(s) if s.isdigit() else -1)
per_cpu = {}
for irq in irqs:
    av = a.get(irq, []); bv = b.get(irq, [])
    n = max(len(av), len(bv))
    for cpu in range(n):
        d = (bv[cpu] if cpu<len(bv) else 0) - (av[cpu] if cpu<len(av) else 0)
        if d > 0:
            per_cpu[cpu] = per_cpu.get(cpu, 0) + d
total = sum(per_cpu.values())
if total == 0:
    print("  (no delta)")
else:
    print(f"  total interrupts delta for {iface}: {total}")
    for cpu, d in sorted(per_cpu.items(), key=lambda x: -x[1])[:10]:
        pct = 100.0*d/total
        print(f"  CPU {cpu:3d}: {d:10d} ({pct:5.1f}%)")
PY
}

{
  echo "Phase 3 DROP — summary $(date -Is)"
  echo "iface=$IFACE  drop_duration=${DURATION_DROP}s  window=${DURATION_WINDOW}s"
  echo "IRQ spread applied: $( ((IRQ_SPREAD_APPLIED==1)) && echo yes || echo no )"
  echo ""
  echo "----- WINDOW A (baseline, no xdpflowd) — mpstat Average -----"
  summarize_mpstat "$A_DIR/mpstat.txt"
  echo ""
  echo "  interrupts per CPU (delta during window):"
  interrupts_delta_per_cpu "$A_DIR/interrupts.before" "$A_DIR/interrupts.after" "$IFACE"
  echo ""
  echo "----- WINDOW B (xdpflowd XDP_${XDP_ACTION^^}) — mpstat Average -----"
  summarize_mpstat "$B_DIR/mpstat.txt"
  echo ""
  echo "  interrupts per CPU (delta during window):"
  interrupts_delta_per_cpu "$B_DIR/interrupts.before" "$B_DIR/interrupts.after" "$IFACE"
  echo ""
  echo "----- bpftool prog profile (xdp_flow_prog during WINDOW B) -----"
  if [[ -s "$B_DIR/bpftool_profile.txt" ]]; then
    cat "$B_DIR/bpftool_profile.txt"
  else
    echo "  (no profile data)"
  fi
  echo ""
  echo "----- NIC rate per window (from sysfs deltas) -----"
  sysfs_window_rate() {
    local dir=$1 dur=$2
    local pb=$(cat "$dir/rx_packets.before" 2>/dev/null || echo 0)
    local pa=$(cat "$dir/rx_packets.after"  2>/dev/null || echo 0)
    local bb=$(cat "$dir/rx_bytes.before"   2>/dev/null || echo 0)
    local ba=$(cat "$dir/rx_bytes.after"    2>/dev/null || echo 0)
    local fb=$(cat "$dir/rx_fifo_errors.before" 2>/dev/null || echo 0)
    local fa=$(cat "$dir/rx_fifo_errors.after"  2>/dev/null || echo 0)
    local dp=$((pa - pb)); local db=$((ba - bb)); local df=$((fa - fb))
    local pps=$(( dp / dur ))
    local bps=$(( db * 8 / dur ))   # bits/sec
    local fps=$(( df / dur ))
    printf "  rx: %'d pps  %'d bits/sec  |  fifo_drops: %'d total  %'d drops/sec\n" \
      "$pps" "$bps" "$df" "$fps"
  }
  echo "A (baseline, ipt_NETFLOW):"
  sysfs_window_rate "$A_DIR" "$DURATION_WINDOW"
  echo "B (xdpflowd XDP_${XDP_ACTION^^}):"
  sysfs_window_rate "$B_DIR" "$DURATION_WINDOW"
  echo ""
  echo "----- NIC fifo_errors lifecycle -----"
  fifo_delta_rate() {
    local before_file=$1 after_file=$2 dur=$3 label=$4
    local before=$(cat "$before_file" 2>/dev/null || echo 0)
    local after=$(cat "$after_file" 2>/dev/null || echo 0)
    local delta=$((after - before))
    local rate=$(( delta / dur ))
    printf "  %-28s delta=%'d  rate=%'d drops/sec\n" "$label" "$delta" "$rate"
  }
  fifo_delta_rate "$A_DIR/rx_fifo_errors.before" "$A_DIR/rx_fifo_errors.after" "$DURATION_WINDOW" "baseline window"
  fifo_delta_rate "$B_DIR/rx_fifo_errors.before" "$B_DIR/rx_fifo_errors.after" "$DURATION_WINDOW" "XDP window"
  fifo_delta_rate "$WORKDIR/rx_fifo_errors.full_before" "$WORKDIR/rx_fifo_errors.full_after" "$DURATION_DROP" "full swap duration"
  if [[ -s "$WORKDIR/rx_fifo_errors.post_test.txt" ]]; then
    echo "  post-test windows:"
    sed 's/^/    /' "$WORKDIR/rx_fifo_errors.post_test.txt"
  else
    echo "  post-test windows: (not collected)"
  fi
  echo ""
  echo "----- ClickHouse rows/packets/bytes (${CH_LOOKBACK_MIN}min before vs after) -----"
  if (( HAVE_CH == 1 )); then
    echo "Before switch: $WORKDIR/clickhouse_before_switch.txt"
    sed -n '1,80p' "$WORKDIR/clickhouse_before_switch.txt" 2>/dev/null || true
    echo ""
    echo "After/during switch: $WORKDIR/clickhouse_after_switch.txt"
    sed -n '1,80p' "$WORKDIR/clickhouse_after_switch.txt" 2>/dev/null || true
  else
    echo "  skipped (set CH_PASS; optional CH_TABLE/CH_TIME_EXPR/CH_PACKETS_COL/CH_BYTES_COL)"
  fi
  echo ""
  echo "Full data in: $WORKDIR"
  echo "  A: $A_DIR"
  echo "  B: $B_DIR"
  echo "  prod_ab_swap log: $WORKDIR/prod_ab_swap.log"
} > "$SUMMARY"

# SUMMARY напечатается через trap cleanup
