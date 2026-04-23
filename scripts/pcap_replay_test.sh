#!/usr/bin/env bash
# pcap_replay_test.sh — capture short pcap on IFACE, replay with tcpreplay, compare JSON snapshots.
#
# Usage (as root):
#   IFACE=ens18 ./scripts/pcap_replay_test.sh
#
# Steps:
#   1) Start background traffic (ping + curl) in subshell
#   2) tcpdump -i IFACE -w /tmp/xdpflowd_local.pcap for CAPTURE_SEC seconds
#   3) Start xdpflowd, tcpreplay the pcap at limited rate, compare deltas
#
set -euo pipefail

IFACE="${IFACE:-ens18}"
CAPTURE_SEC="${CAPTURE_SEC:-5}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PCAP="${PCAP:-/tmp/xdpflowd_local.pcap}"
XDPFLOWD_BIN="${XDPFLOWD_BIN:-$ROOT/bin/xdpflowd}"
BPF_O="${BPF_O:-$ROOT/bpf/xdp_flow.o}"
JSONL="${TMPDIR:-/tmp}/xdpflowd_pcap.ndjson"

if [[ "${EUID:-}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

: >"$JSONL"
"$XDPFLOWD_BIN" -iface "$IFACE" -mode native -bpf "$BPF_O" \
  -interval 60s -json-out "$JSONL" -json-interval 2s \
  >/tmp/xdpflowd_pcap.log 2>&1 &
XPID=$!
sleep 2

# Background noise while capturing
( ping -c 20 -i 0.2 127.0.0.1 >/dev/null 2>&1 || true ) &
( for i in 1 2 3; do curl -s --max-time 2 https://example.com >/dev/null || true; done ) &

echo "Capturing $CAPTURE_SEC s to $PCAP ..."
timeout "${CAPTURE_SEC}s" tcpdump -i "$IFACE" -w "$PCAP" -s 256 'not port 22' 2>/dev/null || true
wait || true

read -r R0_PKT R0_BYT <<<"$(ethtool -S "$IFACE" | awk '/^[[:space:]]*rx_packets:/{gsub(/:/,"",$2);pkt=$2} /^[[:space:]]*rx_bytes:/{gsub(/:/,"",$2);byt=$2} END{print pkt+0,byt+0}')"
read -r S0_TP S0_PE S0_MF S0_FP S0_FB <<<"$(tail -n 1 "$JSONL" | jq -r '[.stats.total_packets,.stats.parse_errors,.stats.map_full,.aggregate.sum_flow_packets,.aggregate.sum_flow_bytes]|@tsv')"

echo "Replaying pcap (10 Mbps cap) ..."
tcpreplay -i "$IFACE" -M 10 "$PCAP" || true
sleep 2

read -r R1_PKT R1_BYT <<<"$(ethtool -S "$IFACE" | awk '/^[[:space:]]*rx_packets:/{gsub(/:/,"",$2);pkt=$2} /^[[:space:]]*rx_bytes:/{gsub(/:/,"",$2);byt=$2} END{print pkt+0,byt+0}')"
read -r S1_TP S1_PE S1_MF S1_FP S1_FB <<<"$(tail -n 1 "$JSONL" | jq -r '[.stats.total_packets,.stats.parse_errors,.stats.map_full,.aggregate.sum_flow_packets,.aggregate.sum_flow_bytes]|@tsv')"

kill $XPID 2>/dev/null || true
wait $XPID 2>/dev/null || true

echo "=== PCAP replay deltas ==="
echo "ethtool rx_packets $((R1_PKT-R0_PKT)) rx_bytes $((R1_BYT-R0_BYT))"
echo "xdp total_packets $((S1_TP-S0_TP)) parse_errors $((S1_PE-S0_PE)) map_full $((S1_MF-S0_MF))"
echo "aggregate flow pkts $((S1_FP-S0_FP)) bytes $((S1_FB-S0_FB))"
echo "Pcap file: $PCAP (copy off VM for inspection)"
