#!/usr/bin/env bash
# afxdp_netflow_test.sh — afxdpflowd → NetFlow v9 → nfcapd (same idea as netflow_test.sh for xdpflowd).
#
# Prerequisites: veth to a netns with iperf3 client, or traffic into IFACE; nfcapd, iperf3, make.
# Example (your VM):
#   sudo nfcapd -b 127.0.0.1 -p 2056 -w /tmp/nfcap_afx -I afx -t 60 -e &
#   sudo $(pwd)/bin/afxdpflowd -iface veth0 -skb -nf-dst 127.0.0.1:2056 -nf-active 15s -nf-idle 5s -stats 5s
#   sudo ip netns exec testns iperf3 -c 10.200.0.1 -t 20 -P 2
#   nfdump -R /tmp/nfcap_afx -o fmt:%sa,%da,%sp,%dp,%pkt,%byt -q
#
# This script is a non-interactive smoke test when IFACE+REMOTE+iperf3 server exist:
#   sudo ./scripts/afxdp_netflow_test.sh veth0 10.200.0.1
set -euo pipefail
IFACE="${1:-veth0}"
REMOTE="${2:-}"
NFPORT="${NFPORT:-2056}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${EUID:-}" -ne 0 ]]; then
  echo "Run as root (AF_XDP + nfcapd)" >&2
  exit 1
fi
command -v nfcapd >/dev/null && command -v nfdump >/dev/null && command -v make >/dev/null || { echo "install nfdump, make" >&2; exit 1; }

W="/tmp/afxdp_nf_test_$$"
mkdir -p "$W"
NF_LOG="$W/nfcapd.log"
: > "$NF_LOG"

make build-afxdp
BIN="$ROOT/bin/afxdpflowd"
[[ -x "$BIN" ]] || exit 1

# Optional: kill old nfcapd on this port
if ss -ulnp 2>/dev/null | grep -q ":$NFPORT "; then
  echo "port $NFPORT busy — set NFPORT=other or free the port" >&2
  exit 1
fi

nfcapd -b 127.0.0.1 -p "$NFPORT" -w "$W" -I afx -t 60 -e >> "$NF_LOG" 2>&1 &
NFPID=$!
sleep 1
kill -0 "$NFPID" 2>/dev/null || { echo "nfcapd failed:"; cat "$NF_LOG"; exit 1; }

cleanup() { kill -TERM "$NFPID" 2>/dev/null || true; wait "$NFPID" 2>/dev/null || true; }
trap cleanup EXIT

timeout 60 "$BIN" -iface "$IFACE" -skb -nf-dst "127.0.0.1:$NFPORT" -nf-active 15s -nf-idle 5s -stats 4s 2> "$W/afx_err.log" &
APID=$!
sleep 2
if [[ -n "$REMOTE" ]] && command -v iperf3 >/dev/null; then
  iperf3 -c "$REMOTE" -t 15 -P 2 || true
else
  echo "Set REMOTE (iperf3 server IP reachable from this host) or generate traffic to $IFACE and wait..."
  sleep 20
fi
kill -INT "$APID" 2>/dev/null || true
wait "$APID" 2>/dev/null || true

echo "--- nfdump (any flows) ---"
nfdump -R "$W" -o raw -q 2>/dev/null | head -n 20 || true
echo "Data dir: $W"
