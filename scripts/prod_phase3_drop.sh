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

set -euo pipefail

DURATION_DROP="${DURATION_DROP:-${1:-120}}"
IFACE="${2:-enp5s0d1}"
DURATION_WINDOW="${DURATION_WINDOW:-30}"
SKIP_IRQ_TUNE="${SKIP_IRQ_TUNE:-0}"
AUTO_IRQ="${AUTO_IRQ:-0}"
CPU_LIST="${CPU_LIST:-}"
XDP_MODE="${XDP_MODE:-native}"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TS="$(date +%Y%m%d_%H%M%S)"
WORKDIR="/tmp/phase3_drop_$TS"
mkdir -p "$WORKDIR"

A_DIR="$WORKDIR/A_baseline"       # замер A: без xdpflowd
B_DIR="$WORKDIR/B_xdpdrop"        # замер B: xdpflowd в DROP
mkdir -p "$A_DIR" "$B_DIR"

LOG="$WORKDIR/orchestrator.log"
SUMMARY="$WORKDIR/SUMMARY.txt"

exec > >(tee -a "$LOG") 2>&1

echo "======================================================================"
echo "Phase 3 DROP test — $TS"
echo "iface=$IFACE  xdp-mode=$XDP_MODE  drop_duration=${DURATION_DROP}s"
echo "workdir=$WORKDIR"
echo "======================================================================"

# ---------- проверки ----------
for c in mpstat ethtool ip bpftool; do
  command -v "$c" >/dev/null || { echo "ERROR: missing $c (apt install sysstat ethtool iproute2 linux-tools-\$(uname -r))"; exit 1; }
done

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

  # mpstat — фон, записывает в файл
  mpstat -P ALL 5 "$((dur / 5))" > "$dir/mpstat.txt" 2>&1 &
  MPSTAT_PID=$!

  # perf top на 10 сек если есть
  if command -v perf >/dev/null 2>&1; then
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
  if (( with_prog == 1 )); then
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

  # сохранить NIC counters
  ip -s link show "$IFACE" > "$dir/ip_s_link.txt" 2>&1 || true
  ethtool -S "$IFACE" > "$dir/ethtool_S.txt" 2>&1 || true

  echo "[WINDOW $name] done."
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

# ---------- 5) Запуск prod_ab_swap с XDP_ACTION=drop в фоне ----------
echo ""
echo "===== Starting prod_ab_swap (XDP_ACTION=drop, ${DURATION_DROP}s) ====="
(
  XDP_ACTION=drop "$REPO_ROOT/scripts/prod_ab_swap.sh" \
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
echo "===== WINDOW B: xdpflowd XDP_DROP ====="
collect_window B "$B_DIR" 1

# ---------- 7) дождаться окончания swap ----------
echo ""
echo "Waiting for prod_ab_swap to finish..."
wait "$SWAP_PID" || true

# ---------- 8) сравнительный отчёт ----------
echo ""
echo "===== BUILDING SUMMARY ====="

summarize_mpstat() {
  local f=$1
  # "Average:  all  user nice sys iowait irq soft steal guest gnice idle"
  awk '
    /^Average:/ && $2=="all" { printf "  all: usr=%s sys=%s soft=%s idle=%s\n", $4, $6, $9, $NF; next }
    /^Average:/ && $2 ~ /^[0-9]+$/ {
      softirq=$9
      if (softirq+0 > 10) printf "  CPU %s: softirq=%s%% idle=%s%%\n", $2, softirq, $NF
    }
  ' "$f"
}

interrupts_delta_per_cpu() {
  local before=$1 after=$2 iface=$3
  # вычислить delta per CPU для строк, где имя содержит iface
  python3 - "$before" "$after" "$iface" <<'PY' 2>/dev/null || return 0
import sys, re
before, after, iface = sys.argv[1], sys.argv[2], sys.argv[3]
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
            if iface in name:
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
  echo "----- WINDOW B (xdpflowd XDP_DROP) — mpstat Average -----"
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
  echo "----- NIC counters delta -----"
  echo "A (ethtool -S drops/fifo):"
  grep -E 'drop|fifo|discard|missed' "$A_DIR/ethtool_S.txt" 2>/dev/null | head -20 || true
  echo ""
  echo "B (ethtool -S drops/fifo):"
  grep -E 'drop|fifo|discard|missed' "$B_DIR/ethtool_S.txt" 2>/dev/null | head -20 || true
  echo ""
  echo "Full data in: $WORKDIR"
  echo "  A: $A_DIR"
  echo "  B: $B_DIR"
  echo "  prod_ab_swap log: $WORKDIR/prod_ab_swap.log"
} > "$SUMMARY"

# SUMMARY напечатается через trap cleanup
