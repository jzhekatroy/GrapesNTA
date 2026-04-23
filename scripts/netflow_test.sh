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
# Run foreground + background-shell so we keep the PID and get all output.
# -t 60: rotation interval; SIGTERM will cause nfcapd to flush the current file.
nfcapd -b 127.0.0.1 -p "$NFPORT" -l "$NFDIR" -I xdp -t 60 \
  >> "$WORKDIR/nfcapd.log" 2>&1 &
NFCAPD_PID=$!
sleep 1
if ! kill -0 "$NFCAPD_PID" 2>/dev/null; then
  echo "  ERROR: nfcapd failed to start — tail of $WORKDIR/nfcapd.log:"
  tail -20 "$WORKDIR/nfcapd.log" | sed 's/^/    /'
  exit 1
fi
echo "  nfcapd pid=$NFCAPD_PID"

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

# --- Stop nfcapd (SIGTERM triggers flush of the current buffer to disk) -------
if kill -0 "$NFCAPD_PID" 2>/dev/null; then
  kill -TERM "$NFCAPD_PID" 2>/dev/null || true
  # Give nfcapd up to 5 s to flush and exit cleanly
  for _ in 1 2 3 4 5; do
    kill -0 "$NFCAPD_PID" 2>/dev/null || break
    sleep 1
  done
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
if [[ -s "$JSON" ]]; then
  tail -1 "$JSON" | python3 -c '
import json, sys
d = json.loads(sys.stdin.read())
s = d["stats"]
a = d["aggregate"]
print("  total_packets:    %d" % s["total_packets"])
print("  parse_errors:     %d" % s["parse_errors"])
print("  map_full:         %d" % s["map_full"])
print("  non_ip_pass:      %d" % s["non_ip_pass"])
print("  sum_flow_packets: %d" % a["sum_flow_packets"])
print("  sum_flow_bytes:   %d" % a["sum_flow_bytes"])
print("  flows_in_map:     %d" % a["flows_in_map"])
'
else
  echo "  (no NDJSON snapshot produced — check $LOG)"
fi
echo

echo "--- nfcapd status ---"
echo "  directory listing:"
ls -la "$NFDIR" 2>/dev/null | sed 's/^/    /'
echo "  nfcapd.log tail:"
tail -10 "$WORKDIR/nfcapd.log" 2>/dev/null | sed 's/^/    /'
echo

echo "--- nfcapd-collected NetFlow v9 flows (top-20 by bytes) ---"
# Any file in $NFDIR starts with "nfcapd." (current or rotated); -R reads all.
if ls "$NFDIR"/nfcapd.* >/dev/null 2>&1; then
  nfdump -R "$NFDIR" -o long -c 20 2>&1 | head -30
else
  echo "  (no nfcapd files produced)"
fi
echo

echo "--- nfcapd grand totals (all records) ---"
if ls "$NFDIR"/nfcapd.* >/dev/null 2>&1; then
  nfdump -R "$NFDIR" -n 0 2>&1 | tail -15
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
