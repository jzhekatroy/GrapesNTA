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
# truncate logs from previous runs so error output is unambiguous
: > "$LOG"
: > "$JSON"
: > "$WORKDIR/nfcapd.log"
: > "$WORKDIR/tcpdump.log"
rm -f "$NFDIR"/nfcapd.* "$WORKDIR/nfv9.pcap"

# Kill any stale nfcapd/tcpdump from earlier aborted runs on the same port.
cleanup_stale() {
  if ss -ulnp 2>/dev/null | grep -q ":$NFPORT "; then
    echo "  note: port $NFPORT is busy, killing listeners..."
    ss -ulnp 2>/dev/null | awk -v p=":$NFPORT " '$0 ~ p {print}' | \
      grep -oE 'pid=[0-9]+' | awk -F= '{print $2}' | \
      while read -r pid; do kill -TERM "$pid" 2>/dev/null || true; done
    sleep 1
  fi
  pkill -f "nfcapd.*$NFPORT" 2>/dev/null || true
  pkill -f "tcpdump.*$NFPORT" 2>/dev/null || true
  sleep 0.5
}
cleanup_stale
trap 'cleanup_stale' EXIT

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

# Packet capture on loopback — lets us verify our NFv9 datagrams are actually
# arriving at :2055 regardless of what nfcapd decides to do with them.
if have tcpdump; then
  echo "[start] tcpdump capturing NFv9 on lo → $WORKDIR/nfv9.pcap"
  tcpdump -U -i lo -w "$WORKDIR/nfv9.pcap" "udp port $NFPORT" \
    >>"$WORKDIR/tcpdump.log" 2>&1 &
  TCPDUMP_PID=$!
  sleep 0.5
fi

echo "[start] nfcapd on 127.0.0.1:$NFPORT → $NFDIR"
# Modern nfdump uses -w for output dir (-l is legacy). Both work for now.
# -t 60: rotation interval; SIGHUP flushes, SIGTERM stops with final flush.
# -e: emit the flow stream to stderr so nfcapd.log shows activity even when
#     no file is produced yet.
nfcapd -b 127.0.0.1 -p "$NFPORT" -w "$NFDIR" -I xdp -t 60 -e \
  >> "$WORKDIR/nfcapd.log" 2>&1 &
NFCAPD_PID=$!
sleep 1
if ! kill -0 "$NFCAPD_PID" 2>/dev/null; then
  echo "  ERROR: nfcapd failed to start — full nfcapd.log:"
  cat "$WORKDIR/nfcapd.log" | sed 's/^/    /'
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

# --- Stop nfcapd (SIGHUP flushes & rotates; then SIGTERM exits cleanly) -------
if kill -0 "$NFCAPD_PID" 2>/dev/null; then
  # Force a rotation so even if the -t window hasn't closed, a file is written.
  kill -HUP "$NFCAPD_PID" 2>/dev/null || true
  sleep 1
  kill -TERM "$NFCAPD_PID" 2>/dev/null || true
  for _ in 1 2 3 4 5; do
    kill -0 "$NFCAPD_PID" 2>/dev/null || break
    sleep 1
  done
fi

# Stop packet capture
if [[ -n "${TCPDUMP_PID:-}" ]] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
  kill -TERM "$TCPDUMP_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true
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

echo "--- NFv9 UDP datagrams captured on loopback ---"
if [[ -s "$WORKDIR/nfv9.pcap" ]]; then
  pcap_bytes=$(stat -c %s "$WORKDIR/nfv9.pcap" 2>/dev/null || wc -c <"$WORKDIR/nfv9.pcap")
  echo "  pcap: $WORKDIR/nfv9.pcap  ($pcap_bytes bytes)"
  if have tcpdump; then
    pkt_count=$(tcpdump -r "$WORKDIR/nfv9.pcap" 2>/dev/null | wc -l)
    echo "  datagrams observed: $pkt_count"
    echo "  first 3 datagrams:"
    tcpdump -r "$WORKDIR/nfv9.pcap" -nn -c 3 2>/dev/null | sed 's/^/    /'
  fi
else
  echo "  (no pcap — tcpdump missing or capture failed)"
fi
echo

echo "--- nfcapd status ---"
echo "  directory listing:"
ls -la "$NFDIR" 2>/dev/null | sed 's/^/    /'
echo "  nfcapd.log (full):"
cat "$WORKDIR/nfcapd.log" 2>/dev/null | sed 's/^/    /'
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
