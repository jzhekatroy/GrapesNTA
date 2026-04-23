#!/usr/bin/env bash
# netflow_test.sh — verify xdpflowd NetFlow v9 export end-to-end.
#
# Setup:
#   - on $REMOTE_HOST (another machine): run  iperf3 -s -p 5201
#   - on this VM the script:
#       - builds + launches xdpflowd on $IFACE with NFv9 → 127.0.0.1:$NFPORT
#       - starts nfcapd listening on 127.0.0.1:$NFPORT → $NFDIR
#       - runs  iperf3 -c $REMOTE_HOST -R  so traffic flows INTO this VM
#   - After the run we:
#       1. compare ethtool/sysfs RX counters vs xdpflowd's final JSON snapshot (accuracy)
#       2. parse nfcapd files with nfdump, sum bytes/packets, compare vs JSON
#       3. check that IP/port of our iperf3 client appears in nfdump output
#
# Requires: iperf3, nfcapd (nfdump package), sudo for xdpflowd.
#
# Usage: sudo ./scripts/netflow_test.sh [IFACE] [REMOTE_HOST]
#   IFACE       — interface where the VM receives iperf3 traffic (default ens18)
#   REMOTE_HOST — IP/hostname that runs `iperf3 -s` (default 192.168.64.1)

set -u

IFACE="${1:-ens18}"
REMOTE_HOST="${2:-192.168.64.1}"
NFPORT="${NFPORT:-2055}"
DURATION="${DURATION:-20}"
WORKDIR="$(pwd)/.nftest"
LOG="$WORKDIR/run.log"
JSON="$WORKDIR/xdpflowd.ndjson"
NFDIR="$WORKDIR/nfcapd"

mkdir -p "$WORKDIR" "$NFDIR"
: > "$LOG"
: > "$JSON"

have() { command -v "$1" >/dev/null 2>&1; }

for bin in iperf3 nfcapd nfdump ethtool make clang; do
  if ! have "$bin"; then
    echo "missing required command: $bin" >&2
    exit 1
  fi
done

echo "[build] compiling BPF object + xdpflowd binary..."
PATH="$PATH:/usr/local/go/bin:/usr/lib/go-1.23/bin" \
  make >> "$LOG" 2>&1 || { echo "make failed; see $LOG"; exit 1; }

XDPFLOWD="$(pwd)/bin/xdpflowd"
BPFOBJ="$(pwd)/bpf/xdp_flow.o"
[[ -x "$XDPFLOWD" ]] || { echo "xdpflowd binary not found at $XDPFLOWD"; exit 1; }

# --- Start collectors ---------------------------------------------------------
echo "[start] nfcapd on 127.0.0.1:$NFPORT → $NFDIR"
nfcapd -b 127.0.0.1 -p "$NFPORT" -l "$NFDIR" -I xdp -D \
  -P "$WORKDIR/nfcapd.pid" \
  -t 60 >> "$LOG" 2>&1 &
sleep 1

# NOTE: iperf3 server must already be running on $REMOTE_HOST (port 5201).
# We use -R on the client so the server pushes traffic TO this VM, which is
# what our XDP program needs to observe on $IFACE.
#
#   On $REMOTE_HOST:  iperf3 -s -p 5201
#   On this VM:       (this script) runs iperf3 -c $REMOTE_HOST -R

# --- Sample RX counters before run --------------------------------------------
read_rx() {
  cat "/sys/class/net/$IFACE/statistics/rx_packets" 2>/dev/null || echo 0
  cat "/sys/class/net/$IFACE/statistics/rx_bytes" 2>/dev/null || echo 0
}
rx0=( $(read_rx) )

# --- Start xdpflowd -----------------------------------------------------------
echo "[start] xdpflowd (NFv9 → 127.0.0.1:$NFPORT, json → $JSON)"
sudo -E "$XDPFLOWD" \
  -bpf "$BPFOBJ" \
  -iface "$IFACE" \
  -mode generic \
  -interval 2s \
  -json-out "$JSON" \
  -json-interval 2s \
  -json-include-flows \
  -nf-dst "127.0.0.1:$NFPORT" \
  -nf-active 5s \
  -nf-idle 3s \
  -nf-template-interval 5s \
  -nf-scan 1s >> "$LOG" 2>&1 &
XDP_PID=$!
sleep 3

# --- Traffic generation -------------------------------------------------------
echo "[traffic] iperf3 reverse from $REMOTE_HOST for ${DURATION}s (~500Mbps UDP)"
# Use -R so the server (this VM) receives; bitrate moderate to avoid FIFO drops
iperf3 -c "$REMOTE_HOST" -u -b 500M -t "$DURATION" -R --logfile "$WORKDIR/iperf3_client.log" >/dev/null 2>&1 || true

# Let idle timeout fire so we flush the active flow
echo "[wait] letting idle timeout expire (6s)"
sleep 6

# --- Graceful shutdown of xdpflowd (triggers final flushAll) ------------------
sudo kill -TERM "$XDP_PID" 2>/dev/null || true
wait "$XDP_PID" 2>/dev/null || true

# Post-shutdown RX counters
rx1=( $(read_rx) )

# --- Stop nfcapd (signal rotates the active file so it becomes readable) ------
if [[ -f "$WORKDIR/nfcapd.pid" ]]; then
  kill "$(cat "$WORKDIR/nfcapd.pid")" 2>/dev/null || true
  sleep 1
fi

# --- Analysis ----------------------------------------------------------------
echo
echo "==================== RESULTS ===================="
echo "Interface:          $IFACE"
echo "Remote (iperf3 -s): $REMOTE_HOST"
echo

echo "--- NIC (sysfs) deltas over the whole run ---"
d_rx_pkts=$(( rx1[0] - rx0[0] ))
d_rx_bytes=$(( rx1[1] - rx0[1] ))
printf "  rx_packets: %d\n  rx_bytes:   %d\n" "$d_rx_pkts" "$d_rx_bytes"
echo

echo "--- xdpflowd final JSON snapshot ---"
# Last line of NDJSON is the final flush (flushFinal())
tail -1 "$JSON" | python3 -c '
import json, sys
d = json.loads(sys.stdin.read())
s, a = d["stats"], d["aggregate"]
print(f"  total_packets:    {s[\"total_packets\"]}")
print(f"  parse_errors:     {s[\"parse_errors\"]}")
print(f"  map_full:         {s[\"map_full\"]}")
print(f"  non_ip_pass:      {s[\"non_ip_pass\"]}")
print(f"  sum_flow_packets: {a[\"sum_flow_packets\"]}")
print(f"  sum_flow_bytes:   {a[\"sum_flow_bytes\"]}")
print(f"  flows_in_map:     {a[\"flows_in_map\"]}")
'
echo

echo "--- nfcapd-collected NetFlow v9 flows (top-20 by bytes) ---"
# Any file in $NFDIR starts with "nfcapd." (current or rotated); -R reads all.
if ls "$NFDIR"/nfcapd.* >/dev/null 2>&1; then
  nfdump -R "$NFDIR" -o 'fmt:%ts %td %pr %sap -> %dap %pkt %byt %fl' -c 20 2>&1 | head -30
else
  echo "  (no nfcapd files produced — check $LOG)"
fi
echo

echo "--- nfcapd aggregate sums (all collected records) ---"
if ls "$NFDIR"/nfcapd.* >/dev/null 2>&1; then
  nfdump -R "$NFDIR" -q -a -A proto -o 'fmt:%pr sum_pkts=%pkt sum_bytes=%byt flows=%fl' 2>&1 | head -10
  echo
  echo "  Grand totals:"
  nfdump -R "$NFDIR" -s any/bytes -q 2>&1 | grep -E '^Summary:' -A 2 || true
  # A portable total: nfdump -R ... -o csv and awk
  echo
  echo "  Totals via CSV parse:"
  nfdump -R "$NFDIR" -q -o csv 2>/dev/null | \
    awk -F, 'NR>1 && NF>8 {p+=$12; b+=$13} END {printf "    records: %d  sum_pkts: %d  sum_bytes: %d\n", NR-1, p, b}'
else
  echo "  (no nfcapd files)"
fi
echo

echo "--- iperf3 client report tail ---"
tail -15 "$WORKDIR/iperf3_client.log" 2>/dev/null | sed 's/^/  /' || echo "  (no iperf3 client log)"
echo

echo "--- Logs ---"
echo "  Run log:      $LOG"
echo "  NDJSON:       $JSON"
echo "  nfcapd dir:   $NFDIR"
echo "  iperf3 cli:   $WORKDIR/iperf3_client.log  (iperf3 -s runs on $REMOTE_HOST)"
echo
echo "==================== EXPECTATIONS ===================="
echo "1. sum_flow_packets ≈ d_rx_pkts   (within a few thousand — FIFO + timing race)"
echo "2. nfdump sum_pkts  ≈ sum_flow_packets"
echo "3. A flow with src=$REMOTE_HOST:5201 → dst=<this VM>:<port> proto=UDP must appear"
echo "4. tcp_flags visible if you switch iperf3 to TCP (-c without -u)"
echo "5. NIC FIFO errors should stay ~0 at 500 Mbps"
