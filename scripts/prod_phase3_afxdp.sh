#!/usr/bin/env bash
# prod_phase3_afxdp.sh — тот же сценарий, что prod_phase3_drop.sh, но для AF_XDP + prod_ab_swap_afxdp.sh
#
# Отличия от xdpflowd-версии:
#   * нет XDP_ACTION (pass|drop) — у afxdpflowd другая модель; RX на iface забирается в userspace;
#   * XDP_MODE=n|g → AFXDP_SKB=0|1 (generic = -skb, как в вашем generic-утре для xdpflowd);
#   * окно B: bpftool profile по xdp_flow_prog не используется (другой BPF стек; см. perf_top).

set -euo pipefail

DURATION_DROP="${DURATION_DROP:-${1:-120}}"
IFACE="${2:-enp5s0d1}"
DURATION_WINDOW="${DURATION_WINDOW:-30}"
SKIP_IRQ_TUNE="${SKIP_IRQ_TUNE:-0}"
AUTO_IRQ="${AUTO_IRQ:-0}"
CPU_LIST="${CPU_LIST:-}"
# Совместимость с утренней командой: XDP_MODE=generic → AFXDP_SKB=1
XDP_MODE="${XDP_MODE:-native}"
case "$XDP_MODE" in
  native)  AFXDP_SKB=0 ;;
  generic) AFXDP_SKB=1 ;;
  *) echo "ERROR: XDP_MODE must be native|generic (got: $XDP_MODE)"; exit 1 ;;
esac
export AFXDP_SKB

# Опционально: те же dest, что в prod_ab_swap_afxdp (по умолчанию localhost collectors)
NF_DSTS="${NF_DSTS:-127.0.0.1:9996,127.0.0.1:9999}"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TS="$(date +%Y%m%d_%H%M%S)"
WORKDIR="/tmp/phase3_afxdp_${XDP_MODE}_$TS"
mkdir -p "$WORKDIR"

A_DIR="$WORKDIR/A_baseline"
B_DIR="$WORKDIR/B_afxdp"
mkdir -p "$A_DIR" "$B_DIR"

LOG="$WORKDIR/orchestrator.log"
SUMMARY="$WORKDIR/SUMMARY.txt"

exec > >(tee -a "$LOG") 2>&1

echo "======================================================================"
echo "Phase 3 AF_XDP test — $TS"
echo "iface=$IFACE  XDP_MODE=$XDP_MODE (AFXDP_SKB=$AFXDP_SKB)  duration=${DURATION_DROP}s  nf-dst=$NF_DSTS"
echo "workdir=$WORKDIR"
echo "======================================================================"

for c in mpstat ethtool ip; do
  command -v "$c" >/dev/null || { echo "ERROR: missing $c (apt install sysstat ethtool iproute2)"; exit 1; }
done
HAVE_PERF=0
command -v perf >/dev/null && HAVE_PERF=1 || \
  echo "NOTE: perf not installed — top kernel functions will be skipped (try: apt install linux-perf)"

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "ERROR: interface $IFACE not found"; exit 1
fi

if ! command -v go >/dev/null; then
  echo "ERROR: go not in PATH (needed for make build-afxdp)"; exit 1
fi
if [[ ! -x ./bin/afxdpflowd ]]; then
  echo "Building afxdpflowd..."
  make -s build-afxdp
fi
[[ -x ./bin/afxdpflowd ]] || { echo "ERROR: ./bin/afxdpflowd missing after build"; exit 1; }

collect_window() {
  local name=$1
  local dir=$2
  # AF_XDP: не ищем xdp_flow_prog в bpftool (другой набор прог);
  # оставляем mpstat + interrupts + (опц.) perf.
  local _unused=${3:-0}

  local dur=$DURATION_WINDOW

  echo ""
  echo "[WINDOW $name] starting — ${dur}s mpstat, interrupts, (perf if available)..."

  cp /proc/interrupts "$dir/interrupts.before"

  cat /sys/class/net/"$IFACE"/statistics/rx_fifo_errors \
    > "$dir/rx_fifo_errors.before" 2>/dev/null || echo 0 > "$dir/rx_fifo_errors.before"
  cat /sys/class/net/"$IFACE"/statistics/rx_packets \
    > "$dir/rx_packets.before" 2>/dev/null || echo 0 > "$dir/rx_packets.before"
  cat /sys/class/net/"$IFACE"/statistics/rx_bytes \
    > "$dir/rx_bytes.before" 2>/dev/null || echo 0 > "$dir/rx_bytes.before"

  mpstat -P ALL 5 "$((dur / 5))" > "$dir/mpstat.txt" 2>&1 &
  MPSTAT_PID=$!

  if (( HAVE_PERF == 1 )); then
    (
      HOT_CPU=$(mpstat -P ALL 1 1 2>/dev/null \
                | awk '$3 ~ /^[0-9]+$/ {print $NF,$3}' \
                | sort -rn | head -1 | awk '{print $2}')
      HOT_CPU=${HOT_CPU:-0}
      echo "[WINDOW $name] perf top -C $HOT_CPU for 10s" >&2
      timeout 10 perf top -C "$HOT_CPU" --no-children -g -E 20 2>/dev/null \
        > "$dir/perf_top.txt" || true
    ) &
  fi

  wait "$MPSTAT_PID" || true

  cp /proc/interrupts "$dir/interrupts.after"

  cat /sys/class/net/"$IFACE"/statistics/rx_fifo_errors \
    > "$dir/rx_fifo_errors.after" 2>/dev/null || echo 0 > "$dir/rx_fifo_errors.after"
  cat /sys/class/net/"$IFACE"/statistics/rx_packets \
    > "$dir/rx_packets.after" 2>/dev/null || echo 0 > "$dir/rx_packets.after"
  cat /sys/class/net/"$IFACE"/statistics/rx_bytes \
    > "$dir/rx_bytes.after" 2>/dev/null || echo 0 > "$dir/rx_bytes.after"

  ip -s link show "$IFACE" > "$dir/ip_s_link.txt" 2>&1 || true
  ethtool -S "$IFACE" > "$dir/ethtool_S.txt" 2>&1 || true
  echo "no xdp_flow_prog (AF_XDP path) — use perf_top.txt" > "$dir/bpftool_profile.txt"

  echo "[WINDOW $name] done."
}

if [[ -x "$REPO_ROOT/scripts/prod_snapshot.sh" ]]; then
  "$REPO_ROOT/scripts/prod_snapshot.sh" "$IFACE" > "$WORKDIR/snapshot.log" 2>&1 || true
fi

echo ""
echo "== IRQ state BEFORE =="
"$REPO_ROOT/scripts/prod_tune_irq.sh" show "$IFACE" | tee "$WORKDIR/irq_before.txt" || true

IRQ_SPREAD_APPLIED=0
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

cleanup() {
  local rc=$?
  echo ""
  echo "== CLEANUP (rc=$rc) =="
  if (( IRQ_SPREAD_APPLIED == 1 )); then
    "$REPO_ROOT/scripts/prod_tune_irq.sh" restore "$IFACE" \
      | tee "$WORKDIR/irq_restore.log" || true
  fi
  echo "Results saved to: $WORKDIR"
  if [[ -f "$SUMMARY" ]]; then
    echo ""
    echo "===== SUMMARY ====="
    cat "$SUMMARY"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM HUP

echo ""
echo "===== WINDOW A: baseline (ipt_NETFLOW, no afxdpflowd), after IRQ tune ====="
collect_window A "$A_DIR" 0

echo ""
echo "===== Starting prod_ab_swap_afxdp (${DURATION_DROP}s, AFXDP_SKB=$AFXDP_SKB) ====="
(
  AFXDP_SKB="$AFXDP_SKB" \
    "$REPO_ROOT/scripts/prod_ab_swap_afxdp.sh" \
    "$DURATION_DROP" "$IFACE" "$NF_DSTS" \
    > "$WORKDIR/prod_ab_swap_afxdp.log" 2>&1
) &
SWAP_PID=$!

echo "Waiting for afxdpflowd to start (up to 40s)..."
for i in $(seq 1 40); do
  if grep -q "afxdpflowd up" "$WORKDIR/prod_ab_swap_afxdp.log" 2>/dev/null; then
    echo "afxdpflowd up."
    break
  fi
  if ! kill -0 "$SWAP_PID" 2>/dev/null; then
    echo "ERROR: prod_ab_swap_afxdp died before daemon came up"
    tail -n 40 "$WORKDIR/prod_ab_swap_afxdp.log"
    exit 1
  fi
  sleep 1
done
sleep 5

echo ""
echo "===== WINDOW B: afxdpflowd (AF_XDP, AFXDP_SKB=$AFXDP_SKB) ====="
collect_window B "$B_DIR" 0

echo ""
echo "Waiting for prod_ab_swap_afxdp to finish..."
wait "$SWAP_PID" || true

echo ""
echo "===== BUILDING SUMMARY ====="

summarize_mpstat() {
  local f=$1
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
  echo "Phase 3 AF_XDP — summary $(date -Is)"
  echo "iface=$IFACE  XDP_MODE=$XDP_MODE (AFXDP_SKB=$AFXDP_SKB)  duration=${DURATION_DROP}s  window=${DURATION_WINDOW}s"
  echo "NF_DSTS=$NF_DSTS"
  echo "IRQ spread applied: $( ((IRQ_SPREAD_APPLIED==1)) && echo yes || echo no )"
  echo ""
  echo "----- WINDOW A (baseline, no afxdpflowd) — mpstat Average -----"
  summarize_mpstat "$A_DIR/mpstat.txt"
  echo ""
  echo "  interrupts per CPU (delta during window):"
  interrupts_delta_per_cpu "$A_DIR/interrupts.before" "$A_DIR/interrupts.after" "$IFACE"
  echo ""
  echo "----- WINDOW B (afxdpflowd AF_XDP) — mpstat Average -----"
  summarize_mpstat "$B_DIR/mpstat.txt"
  echo ""
  echo "  interrupts per CPU (delta during window):"
  interrupts_delta_per_cpu "$B_DIR/interrupts.before" "$B_DIR/interrupts.after" "$IFACE"
  echo ""
  echo "----- bpftool xdp_flow_prog: N/A (AF_XDP) — see B/perf_top.txt -----"
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
    local bps=$(( db * 8 / dur ))
    local fps=$(( df / dur ))
    printf "  rx: %'d pps  %'d bits/sec  |  fifo_drops: %'d total  %'d drops/sec\n" \
      "$pps" "$bps" "$df" "$fps"
  }
  echo "A (baseline, ipt_NETFLOW):"
  sysfs_window_rate "$A_DIR" "$DURATION_WINDOW"
  echo "B (afxdpflowd):"
  sysfs_window_rate "$B_DIR" "$DURATION_WINDOW"
  echo ""
  echo "Full data in: $WORKDIR"
  echo "  A: $A_DIR"
  echo "  B: $B_DIR"
  echo "  prod_ab_swap_afxdp log: $WORKDIR/prod_ab_swap_afxdp.log"
} > "$SUMMARY"
