#!/usr/bin/env bash
# accuracy_test.sh — compare XDP program counters vs ethtool NIC stats (strict thresholds).
#
# Environment:
#   IFACE          — interface (default: ens18)
#   IPERF3_HOST    — iperf3 -s reachable host (required for iperf phases)
#   IPERF3_PORT    — default 5201
#   XDPFLOWD_BIN   — path to xdpflowd binary (default: ./bin/xdpflowd)
#   BPF_O          — path to bpf/xdp_flow.o (default: ./bpf/xdp_flow.o)
#   SKIP_IPERF     — set to 1 to skip iperf3 tests (only tcpreplay if PCAP provided)
#   PCAP_IN        — optional: replay this pcap with tcpreplay after iperf
#
# Thresholds (plan):
#   packets: XDP stats total_packets delta vs ethtool rx_packets delta >= 99.99%
#   bytes:   sum(flow.bytes) delta vs ethtool rx_bytes delta >= 99.95%
#
set -euo pipefail

IFACE="${IFACE:-ens18}"
IPERF3_PORT="${IPERF3_PORT:-5201}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
XDPFLOWD_BIN="${XDPFLOWD_BIN:-$ROOT/bin/xdpflowd}"
BPF_O="${BPF_O:-$ROOT/bpf/xdp_flow.o}"
JSONL="${TMPDIR:-/tmp}/xdpflowd_accuracy.ndjson"
THRESH_PKTS="99.99"
THRESH_BYTES="99.95"

need_root() {
  if [[ "${EUID:-}" -ne 0 ]]; then
    echo "Run as root (need XDP attach + ethtool)." >&2
    exit 1
  fi
}

ethtool_rx() {
  local iface="$1"
  # virtio_net: rx_packets / rx_bytes; some drivers use different names — try common keys
  ethtool -S "$iface" 2>/dev/null | awk '
    /^[[:space:]]*rx_packets:/ { gsub(/:/,"",$2); pkt=$2 }
    /^[[:space:]]*rx_bytes:/  { gsub(/:/,"",$2);  byt=$2 }
    END { print pkt+0, byt+0 }
  '
}

read_json_last() {
  local f="$1"
  [[ -f "$f" ]] || { echo "0 0 0 0 0"; return; }
  tail -n 1 "$f" | jq -r '
    [.stats.total_packets, .stats.parse_errors, .stats.map_full,
     .aggregate.sum_flow_packets, .aggregate.sum_flow_bytes] | @tsv
  ' 2>/dev/null || echo "0 0 0 0 0"
}

save_gro_state() {
  ethtool -k "$IFACE" 2>/dev/null | grep -E '^(rx-gro|generic-receive-offload|rx-udp-gro-forwarding):' || true
}

gro_off() {
  ethtool -K "$IFACE" gro off 2>/dev/null || true
  ethtool -K "$IFACE" rx-udp-gro-forwarding off 2>/dev/null || true
}

gro_restore_defaults() {
  ethtool -K "$IFACE" gro on 2>/dev/null || true
}

kill_xdpflowd() {
  if [[ -f /tmp/xdpflowd_accuracy.pid ]]; then
    kill "$(cat /tmp/xdpflowd_accuracy.pid)" 2>/dev/null || true
    rm -f /tmp/xdpflowd_accuracy.pid
  fi
  sleep 0.5
}

start_xdpflowd_bg() {
  kill_xdpflowd
  rm -f "$JSONL"
  : >"$JSONL"
  # Short JSON interval for finer snapshots during iperf
  "$XDPFLOWD_BIN" -iface "$IFACE" -mode native -bpf "$BPF_O" \
    -interval 60s -json-out "$JSONL" -json-interval 2s -json-include-flows=false \
    >/tmp/xdpflowd_accuracy.log 2>&1 &
  echo $! >/tmp/xdpflowd_accuracy.pid
  sleep 2
}

stop_xdpflowd() {
  if [[ -f /tmp/xdpflowd_accuracy.pid ]]; then
    kill "$(cat /tmp/xdpflowd_accuracy.pid)" 2>/dev/null || true
  fi
  kill_xdpflowd
}

compare_deltas() {
  local label="$1"
  local r0_pkt="$2" r0_byt="$3" r1_pkt="$4" r1_byt="$5"
  local s0_pkt="$6" s0_flow_pkt="$7" s0_flow_byt="$8"
  local s1_pkt="$9" s1_flow_pkt="${10}" s1_flow_byt="${11}"

  local drx_pkt=$((r1_pkt - r0_pkt))
  local drx_byt=$((r1_byt - r0_byt))
  local dxdp_pkt=$((s1_pkt - s0_pkt))
  local dflow_pkt=$((s1_flow_pkt - s0_flow_pkt))
  local dflow_byt=$((s1_flow_byt - s0_flow_byt))

  echo "=== $label ==="
  echo "ethtool delta:  rx_packets=$drx_pkt rx_bytes=$drx_byt"
  echo "xdp stats delta total_packets=$dxdp_pkt"
  echo "flows aggregate delta sum_flow_packets=$dflow_pkt sum_flow_bytes=$dflow_byt"

  if [[ "$drx_pkt" -le 0 ]]; then
    echo "WARN: no RX packet delta on interface (wrong iface or idle)."
    return 0
  fi

  local pct_xdp pct_flow_pkts pct_flow_byts
  pct_xdp="$(awk -v a="$dxdp_pkt" -v b="$drx_pkt" 'BEGIN{printf "%.6f", (100.0*a/b)}')"
  pct_flow_pkts="$(awk -v a="$dflow_pkt" -v b="$drx_pkt" 'BEGIN{printf "%.6f", (100.0*a/b)}')"
  pct_flow_byts="$(awk -v a="$dflow_byt" -v b="$drx_byt" 'BEGIN{if(b<=0)print "0"; else printf "%.6f", (100.0*a/b)}')"

  echo "Ratio XDP_stats_pkts vs ethtool_rx_pkts = ${pct_xdp}% (need >= ${THRESH_PKTS}%)"
  echo "Ratio sum_flow_pkts vs ethtool_rx_pkts = ${pct_flow_pkts}%"
  echo "Ratio sum_flow_bytes vs ethtool_rx_bytes = ${pct_flow_byts}% (need >= ${THRESH_BYTES}%)"

  if ! awk -v p="$pct_xdp" -v t="$THRESH_PKTS" 'BEGIN{exit (p+0 >= t+0) ? 0 : 1}'; then
    echo "FAIL: XDP packet ratio below ${THRESH_PKTS}%"
    return 1
  fi
  if ! awk -v p="$pct_flow_byts" -v t="$THRESH_BYTES" 'BEGIN{if (t+0 <= 0) exit 0; exit (p+0 >= t+0) ? 0 : 1}'; then
    echo "WARN: flow bytes ratio below ${THRESH_BYTES}% (non-IP traffic, GRO, or MTU overhead — inspect pcap / ethtool -k)."
  fi
  return 0
}

run_iperf_phase() {
  local proto="$1" # udp or tcp
  need_root
  [[ -n "${IPERF3_HOST:-}" ]] || { echo "Set IPERF3_HOST=ip.of.iperf.server"; exit 1; }
  [[ -f "$XDPFLOWD_BIN" ]] || { echo "Build xdpflowd first: make -C $ROOT"; exit 1; }
  [[ -f "$BPF_O" ]] || { echo "Build BPF first: make -C $ROOT bpf"; exit 1; }

  echo "--- Saving GRO state (informational) ---"
  save_gro_state
  gro_off

  read -r R0_PKT R0_BYT <<<"$(ethtool_rx "$IFACE")"
  start_xdpflowd_bg
  read -r S0_TP S0_PE S0_MF S0_FP S0_FB <<<"$(read_json_last "$JSONL")"

  if [[ "$proto" == "udp" ]]; then
    echo "--- iperf3 UDP 10s ---"
    iperf3 -c "$IPERF3_HOST" -p "$IPERF3_PORT" -u -b 200M -t 10 -l 1200 || true
  else
    echo "--- iperf3 TCP 10s ---"
    iperf3 -c "$IPERF3_HOST" -p "$IPERF3_PORT" -t 10 -P 4 || true
  fi

  sleep 3
  read -r R1_PKT R1_BYT <<<"$(ethtool_rx "$IFACE")"
  read -r S1_TP S1_PE S1_MF S1_FP S1_FB <<<"$(read_json_last "$JSONL")"
  stop_xdpflowd
  gro_restore_defaults

  compare_deltas "iperf3-$proto" \
    "$R0_PKT" "$R0_BYT" "$R1_PKT" "$R1_BYT" \
    "$S0_TP" "$S0_FP" "$S0_FB" \
    "$S1_TP" "$S1_FP" "$S1_FB"
}

run_tcpreplay_phase() {
  [[ -n "${PCAP_IN:-}" ]] || { echo "PCAP_IN not set — skip tcpreplay"; return 0; }
  [[ -f "$PCAP_IN" ]] || { echo "PCAP_IN file missing: $PCAP_IN"; return 1; }
  need_root
  gro_off
  read -r R0_PKT R0_BYT <<<"$(ethtool_rx "$IFACE")"
  start_xdpflowd_bg
  read -r S0_TP S0_PE S0_MF S0_FP S0_FB <<<"$(read_json_last "$JSONL")"
  echo "--- tcpreplay $PCAP_IN (multiplier 10 Mbps) ---"
  tcpreplay -i "$IFACE" -M 10 "$PCAP_IN" || true
  sleep 2
  read -r R1_PKT R1_BYT <<<"$(ethtool_rx "$IFACE")"
  read -r S1_TP S1_PE S1_MF S1_FP S1_FB <<<"$(read_json_last "$JSONL")"
  stop_xdpflowd
  gro_restore_defaults
  compare_deltas "tcpreplay" \
    "$R0_PKT" "$R0_BYT" "$R1_PKT" "$R1_BYT" \
    "$S0_TP" "$S0_FP" "$S0_FB" \
    "$S1_TP" "$S1_FP" "$S1_FB"
}

main() {
  need_root
  command -v jq >/dev/null || { echo "Install jq"; exit 1; }
  command -v ethtool >/dev/null || { echo "Install ethtool"; exit 1; }

  if [[ "${SKIP_IPERF:-0}" != "1" ]]; then
    run_iperf_phase udp
    run_iperf_phase tcp
  fi
  run_tcpreplay_phase || true
  echo "Done. NDJSON log: $JSONL (last lines):"
  tail -n 3 "$JSONL" 2>/dev/null || true
}

main "$@"
