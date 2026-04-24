#!/usr/bin/env bash
# prod_ab_swap_afxdp.sh — кратковременная подмена ipt_NETFLOW -> afxdpflowd (AF_XDP + userspace NFv9).
#
# Аналог prod_ab_swap.sh для xdpflowd, но:
#   * сборка: make build-afxdp
#   * бинарь: ./bin/afxdpflowd (нет -bpf / -xdp-action / -json-out)
#   * watchdog: рост wire_ground_truth "packets" и/или netflow packets_out в общем логе
#
# ВАЖНО: AF_XDP забирает RX с интерфейса — использовать ТОЛЬКО на SPAN/mirror-порту,
# как и XDP_ACTION=drop для xdpflowd. На management-интерфейсе не запускать.
#
# Запуск:
#   sudo ./scripts/prod_ab_swap_afxdp.sh [duration_sec] [iface] [nf_dsts]
# По умолчанию: 600 сек, enp5s0d1, 127.0.0.1:9996,127.0.0.1:9999
#
# Режим XDP для AF_XDP:
#   AFXDP_SKB=0 (default) — native driver XDP (как в afxdpflowd по умолчанию)
#   AFXDP_SKB=1         — generic XDP (-skb), для диагностики / VM
#
# Репетиция (правило не трогаем, бинарь не стартуем):
#   sudo ./scripts/prod_ab_swap_afxdp.sh --dry-run
#   sudo env DRY_RUN=1 ./scripts/prod_ab_swap_afxdp.sh 120 enp5s0d1
#
# Panic restore:
#   sudo ./scripts/prod_restore.sh /tmp/afxdpflowd_abswap_<TS>/state.env

set -euo pipefail

# DRY_RUN=1 из окружения: sudo env DRY_RUN=1 ./scripts/prod_ab_swap_afxdp.sh …
case "${DRY_RUN:-0}" in
  1) DRY_RUN=1 ;;
  *) DRY_RUN=0 ;;
esac

if [[ "${1:-}" == "--dry-run" || "${1:-}" == "-n" ]]; then
  DRY_RUN=1
  shift
fi

DURATION="${1:-600}"
IFACE="${2:-enp5s0d1}"
NF_DSTS="${3:-127.0.0.1:9996,127.0.0.1:9999}"

AFXDP_SKB="${AFXDP_SKB:-0}"
case "$AFXDP_SKB" in
  0|1) ;;
  *) echo "ERROR: AFXDP_SKB must be 0 or 1 (got: $AFXDP_SKB)" >&2; exit 1;;
esac

MAX_DURATION=3600
if (( DURATION > MAX_DURATION )); then
  echo "ERROR: duration=$DURATION > $MAX_DURATION (hard cap)" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TS="$(date +%Y%m%d_%H%M%S)"
WORKDIR="/tmp/afxdpflowd_abswap_$TS"
IPT_BACKUP="/root/iptables-save-before-afxdp-$TS.txt"
LOG_AFX="$WORKDIR/afxdpflowd.log"
STATE_FILE="$WORKDIR/state.env"

mkdir -p "$WORKDIR"

need_cmd() { command -v "$1" >/dev/null || { echo "ERROR: missing $1" >&2; exit 1; }; }
need_cmd iptables
need_cmd iptables-save
need_cmd iptables-restore
need_cmd make

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
  echo "ERROR: no Go >= 1.21 in PATH" >&2
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

RULE_TABLE=""
RULE_SPEC=""
for t in raw mangle nat; do
  lines=$(iptables-save -t "$t" 2>/dev/null | grep -E "^-A PREROUTING .*-j NETFLOW\b" || true)
  if [ -n "$lines" ]; then
    count=$(printf '%s\n' "$lines" | wc -l | awk '{print $1}')
    if (( count > 1 )); then
      echo "ERROR: found $count NETFLOW rules in table $t — refusing:" >&2
      printf '%s\n' "$lines" >&2
      exit 1
    fi
    if ! printf '%s\n' "$lines" | grep -q -- "-i $IFACE"; then
      echo "WARNING: NETFLOW rule in table $t не относится к $IFACE:" >&2
      printf '%s\n' "$lines" >&2
      continue
    fi
    RULE_TABLE="$t"
    RULE_SPEC=$(printf '%s' "$lines" | sed -E 's/^-A PREROUTING //')
    break
  fi
done

if [ -z "$RULE_TABLE" ] || [ -z "$RULE_SPEC" ]; then
  echo "ERROR: no matching NETFLOW rule for $IFACE in raw/mangle/nat" >&2
  exit 1
fi

echo "[$(date +%T)] found rule: table=$RULE_TABLE PREROUTING $RULE_SPEC"

iptables-save > "$IPT_BACKUP"
echo "[$(date +%T)] iptables backup: $IPT_BACKUP"

if ! iptables -t "$RULE_TABLE" -C PREROUTING $RULE_SPEC 2>/dev/null; then
  echo "ERROR: iptables -C does not confirm rule" >&2
  exit 1
fi

SKB_FLAG=()
if [[ "$AFXDP_SKB" == "1" ]]; then
  SKB_FLAG=(-skb)
fi

AFXDP_CMD=(
  ./bin/afxdpflowd
  -iface "$IFACE"
  "${SKB_FLAG[@]}"
  -nf-dst "$NF_DSTS"
  -nf-active "${AFXDP_NF_ACTIVE:-1800s}"
  -nf-idle "${AFXDP_NF_IDLE:-15s}"
  -nf-template-interval "${AFXDP_NF_TMPL:-60s}"
  -nf-scan "${AFXDP_NF_SCAN:-1s}"
  -stats "${AFXDP_STATS:-5s}"
)

if (( DRY_RUN )); then
  echo ""
  echo "== DRY RUN (afxdpflowd) =="
  echo "Would:"
  echo "  iptables -t $RULE_TABLE -D PREROUTING $RULE_SPEC"
  echo "  make build-afxdp"
  echo "  run: ${AFXDP_CMD[*]}"
  echo "  for ${DURATION}s, then restore rule via trap"
  exit 0
fi

cat > "$STATE_FILE" <<EOF
TS=$TS
IFACE=$IFACE
RULE_TABLE=$RULE_TABLE
RULE_SPEC='$RULE_SPEC'
IPT_BACKUP=$IPT_BACKUP
BASELINE_DIR=$BASELINE_DIR
EOF
echo "[$(date +%T)] state: $STATE_FILE"

: "${GO:=go}"
if [ ! -f go.sum ]; then
  "$GO" mod tidy
fi
echo "[$(date +%T)] building afxdpflowd..."
make -s build-afxdp
[ -x ./bin/afxdpflowd ] || { echo "ERROR: build failed"; exit 1; }

AFX_PID=""
SWAP_DONE=0

restore_rule() {
  if (( SWAP_DONE == 0 )); then
    return 0
  fi
  echo "[$(date +%T)] RESTORE: re-inserting iptables NETFLOW rule..."
  if iptables -t "$RULE_TABLE" -C PREROUTING $RULE_SPEC 2>/dev/null; then
    echo "[$(date +%T)] rule already present"
    SWAP_DONE=0
    return 0
  fi
  if iptables -t "$RULE_TABLE" -I PREROUTING 1 $RULE_SPEC; then
    echo "[$(date +%T)] RESTORE ok"
    SWAP_DONE=0
  else
    echo "CRITICAL: restore failed — iptables -t $RULE_TABLE -I PREROUTING 1 $RULE_SPEC" >&2
    echo "  or: iptables-restore < $IPT_BACKUP" >&2
    echo "  or: ./scripts/prod_restore.sh $STATE_FILE" >&2
  fi
}

run_verify() {
  echo "[$(date +%T)] prod_verify $BASELINE_DIR $IFACE"
  "$REPO_ROOT/scripts/prod_verify.sh" "$BASELINE_DIR" "$IFACE" || true
}

cleanup() {
  local rc=$?
  echo ""
  echo "[$(date +%T)] cleanup (exit=$rc)"
  if [ -n "$AFX_PID" ] && kill -0 "$AFX_PID" 2>/dev/null; then
    kill -TERM "$AFX_PID" 2>/dev/null || true
    for _ in $(seq 1 15); do
      kill -0 "$AFX_PID" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$AFX_PID" 2>/dev/null; then
      echo "[$(date +%T)] WARN: afxdpflowd did not exit in 15s — SIGKILL"
      kill -KILL "$AFX_PID" 2>/dev/null || true
    fi
  fi
  restore_rule
  if [ -n "${BASELINE_DIR:-}" ] && [ -d "$BASELINE_DIR" ]; then
    run_verify
  fi
}
trap cleanup EXIT INT TERM HUP

prepare_memory() {
  echo "[$(date +%T)] memory prep: drop_caches + compact_memory"
  sync
  echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
  echo 1 > /proc/sys/vm/compact_memory 2>/dev/null || true
  sleep 2
}
prepare_memory

echo "[$(date +%T)] removing NETFLOW rule..."
iptables -t "$RULE_TABLE" -D PREROUTING $RULE_SPEC
SWAP_DONE=1

AFX_STDBUF=""
if command -v stdbuf >/dev/null 2>&1; then
  AFX_STDBUF="stdbuf -oL -eL"
fi

{
  echo "=== afxdpflowd launch at $(date -Is) ==="
  echo "cmdline: $AFX_STDBUF ${AFXDP_CMD[*]}"
  echo "WORKDIR: $WORKDIR"
  echo ""
} > "$LOG_AFX"

$AFX_STDBUF "${AFXDP_CMD[@]}" >>"$LOG_AFX" 2>&1 &
AFX_PID=$!

for i in $(seq 1 20); do
  if grep -qE 'afxdpflowd started' "$LOG_AFX" 2>/dev/null; then break; fi
  if ! kill -0 "$AFX_PID" 2>/dev/null; then
    echo "ERROR: afxdpflowd died during startup"
    tail -n 50 "$LOG_AFX"
    exit 1
  fi
  sleep 1
done
echo "[$(date +%T)] afxdpflowd up pid=$AFX_PID log=$LOG_AFX"

# --- watchdog: wire "packets" OR netflow packets_out must advance ---
extract_wire_pkts() {
  grep 'wire_ground_truth' "$LOG_AFX" 2>/dev/null | tail -1 | grep -oE '"packets":[0-9]+' | head -1 | cut -d: -f2 || echo 0
}
extract_nf_pkts_out() {
  grep -oE 'packets_out=[0-9]+' "$LOG_AFX" 2>/dev/null | tail -1 | cut -d= -f2 || echo 0
}

echo "[$(date +%T)] running ${DURATION}s (watchdog: wire packets or packets_out). Ctrl+C restores rule."
last_wire=0
last_nf=0
stall_count=0
remaining=$DURATION
while (( remaining > 0 )); do
  sleep 10
  remaining=$(( remaining - 10 ))

  if ! kill -0 "$AFX_PID" 2>/dev/null; then
    echo "[$(date +%T)] WATCHDOG: afxdpflowd died"
    tail -n 40 "$LOG_AFX"
    exit 1
  fi

  cur_wire=$(extract_wire_pkts)
  cur_nf=$(extract_nf_pkts_out)
  cur_wire=${cur_wire:-0}
  cur_nf=${cur_nf:-0}

  progressed=0
  (( cur_wire > last_wire )) && progressed=1
  (( cur_nf > last_nf )) && progressed=1

  if (( progressed )); then
    stall_count=0
    last_wire=$cur_wire
    last_nf=$cur_nf
  else
    stall_count=$(( stall_count + 1 ))
  fi

  if (( stall_count >= 3 )) && (( DURATION - remaining > 60 )); then
    echo "[$(date +%T)] WATCHDOG: no traffic growth for 30s (wire=$cur_wire nf_out=$cur_nf)"
    exit 1
  fi

  tail_line=$(tail -n 1 "$LOG_AFX" 2>/dev/null | tr -d '\n' | cut -c -160)
  echo "[$(date +%T)] +$((DURATION-remaining))s/${DURATION}s wire=$cur_wire nf_out=$cur_nf  $tail_line"
done

echo "[$(date +%T)] planned duration reached — EXIT triggers trap (stop afxdpflowd, restore rule, prod_verify)."
