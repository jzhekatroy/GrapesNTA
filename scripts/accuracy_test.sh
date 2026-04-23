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
  # Use /sys/class/net/<iface>/statistics — works on every driver (virtio_net,
  # mlx5_core, ixgbe, i40e, etc.). ethtool -S has driver-specific key names.
  local iface="$1"
  local p="/sys/class/net/$iface/statistics"
  local rxp rxb
  rxp="$(cat "$p/rx_packets" 2>/dev/null || echo 0)"
  rxb="$(cat "$p/rx_bytes"   2>/dev/null || echo 0)"
  echo "$rxp $rxb"
}

read_json_last() {
  # Returns 6 numbers: total_packets parse_errors map_full non_ip_pass sum_flow_packets sum_flow_bytes
  local f="$1"
  [[ -f "$f" ]] || { echo "0 0 0 0 0 0"; return; }
  tail -n 1 "$f" | jq -r '
    [.stats.total_packets, .stats.parse_errors, .stats.map_full,
     (.stats.non_ip_pass // 0),
     .aggregate.sum_flow_packets, .aggregate.sum_flow_bytes] | @tsv
  ' 2>/dev/null || echo "0 0 0 0 0 0"
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
  # Send SIGTERM so xdpflowd writes its final NDJSON snapshot before exit.
  if [[ -f /tmp/xdpflowd_accuracy.pid ]]; then
    local pid
    pid="$(cat /tmp/xdpflowd_accuracy.pid)"
    kill -TERM "$pid" 2>/dev/null || true
    # Wait up to 3s for graceful exit (flushFinal in main.go)
    for _ in 1 2 3 4 5 6; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.5
    done
    kill -KILL "$pid" 2>/dev/null || true
    rm -f /tmp/xdpflowd_accuracy.pid
  fi
}

compare_deltas() {
  local label="$1"
  local r0_pkt="$2"        r0_byt="$3"        r1_pkt="$4"        r1_byt="$5"
  local s0_tp="$6"  s0_pe="$7"  s0_mf="$8"  s0_nip="$9"
  local s0_fp="${10}" s0_fb="${11}"
  local s1_tp="${12}" s1_pe="${13}" s1_mf="${14}" s1_nip="${15}"
  local s1_fp="${16}" s1_fb="${17}"

  local drx_pkt=$((r1_pkt - r0_pkt))
  local drx_byt=$((r1_byt - r0_byt))
  local dxdp_tp=$((s1_tp - s0_tp))
  local dxdp_pe=$((s1_pe - s0_pe))
  local dxdp_mf=$((s1_mf - s0_mf))
  local dxdp_nip=$((s1_nip - s0_nip))
  local dflow_pkt=$((s1_fp - s0_fp))
  local dflow_byt=$((s1_fb - s0_fb))
  local identity=$((dflow_pkt + dxdp_pe + dxdp_mf + dxdp_nip))

  echo "=== $label ==="
  echo "sysfs delta:   rx_packets=$drx_pkt rx_bytes=$drx_byt"
  echo "XDP  delta:    total=$dxdp_tp parse_errors=$dxdp_pe map_full=$dxdp_mf non_ip=$dxdp_nip"
  echo "flow delta:    pkts=$dflow_pkt bytes=$dflow_byt"
  echo "identity:      flow + parse_err + map_full + non_ip = $identity (must equal total=$dxdp_tp)"

  if [[ "$identity" -ne "$dxdp_tp" ]]; then
    echo "FAIL: internal identity broken (difference = $((dxdp_tp - identity)) packets)"
    return 1
  else
    echo "PASS: internal identity holds"
  fi

  if [[ "$drx_pkt" -le 0 ]]; then
    echo "WARN: no RX packet delta on interface (wrong iface or idle)."
    return 0
  fi

  local pct_xdp pct_flow_pkts pct_flow_byts
  pct_xdp="$(awk        -v a="$dxdp_tp"   -v b="$drx_pkt" 'BEGIN{printf "%.6f", (100.0*a/b)}')"
  pct_flow_pkts="$(awk  -v a="$dflow_pkt" -v b="$drx_pkt" 'BEGIN{printf "%.6f", (100.0*a/b)}')"
  pct_flow_byts="$(awk  -v a="$dflow_byt" -v b="$drx_byt" 'BEGIN{if(b<=0)print "0"; else printf "%.6f", (100.0*a/b)}')"

  echo "Ratio XDP_total  vs sysfs_rx_pkts  = ${pct_xdp}% (need >= ${THRESH_PKTS}%)"
  echo "Ratio flow_pkts  vs sysfs_rx_pkts  = ${pct_flow_pkts}% (informational; = XDP - parse_err - map_full - non_ip)"
  echo "Ratio flow_bytes vs sysfs_rx_bytes = ${pct_flow_byts}% (need >= ${THRESH_BYTES}%)"

  local rc=0
  if ! awk -v p="$pct_xdp" -v t="$THRESH_PKTS" 'BEGIN{exit (p+0 >= t+0) ? 0 : 1}'; then
    echo "FAIL: XDP packet ratio below ${THRESH_PKTS}%"
    rc=1
  fi
  if ! awk -v p="$pct_flow_byts" -v t="$THRESH_BYTES" 'BEGIN{if (t+0 <= 0) exit 0; exit (p+0 >= t+0) ? 0 : 1}'; then
    echo "WARN: flow bytes ratio below ${THRESH_BYTES}% (GRO, MTU overhead, or non-IP bytes)."
  fi
  return $rc
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

  start_xdpflowd_bg
  read -r S0_TP S0_PE S0_MF S0_NIP S0_FP S0_FB <<<"$(read_json_last "$JSONL")"
  read -r R0_PKT R0_BYT <<<"$(ethtool_rx "$IFACE")"

  if [[ "$proto" == "udp" ]]; then
    echo "--- iperf3 UDP 10s (reverse: server -> VM) ---"
    iperf3 -c "$IPERF3_HOST" -p "$IPERF3_PORT" -u -b 200M -t 10 -l 1200 -R || true
  else
    echo "--- iperf3 TCP 10s (reverse: server -> VM) ---"
    iperf3 -c "$IPERF3_HOST" -p "$IPERF3_PORT" -t 10 -P 4 -R || true
  fi

  # Let in-flight packets settle, then close the timing gap: stop_xdpflowd sends
  # SIGTERM which triggers flushFinal(); read sysfs immediately after for a
  # closely-aligned snapshot.
  sleep 3
  stop_xdpflowd
  read -r R1_PKT R1_BYT <<<"$(ethtool_rx "$IFACE")"
  read -r S1_TP S1_PE S1_MF S1_NIP S1_FP S1_FB <<<"$(read_json_last "$JSONL")"
  gro_restore_defaults

  compare_deltas "iperf3-$proto" \
    "$R0_PKT" "$R0_BYT" "$R1_PKT" "$R1_BYT" \
    "$S0_TP" "$S0_PE" "$S0_MF" "$S0_NIP" "$S0_FP" "$S0_FB" \
    "$S1_TP" "$S1_PE" "$S1_MF" "$S1_NIP" "$S1_FP" "$S1_FB"
}

run_tcpreplay_phase() {
  [[ -n "${PCAP_IN:-}" ]] || { echo "PCAP_IN not set — skip tcpreplay"; return 0; }
  [[ -f "$PCAP_IN" ]] || { echo "PCAP_IN file missing: $PCAP_IN"; return 1; }
  need_root
  gro_off
  start_xdpflowd_bg
  read -r S0_TP S0_PE S0_MF S0_NIP S0_FP S0_FB <<<"$(read_json_last "$JSONL")"
  read -r R0_PKT R0_BYT <<<"$(ethtool_rx "$IFACE")"
  echo "--- tcpreplay $PCAP_IN (multiplier 10 Mbps) ---"
  tcpreplay -i "$IFACE" -M 10 "$PCAP_IN" || true
  sleep 2
  stop_xdpflowd
  read -r R1_PKT R1_BYT <<<"$(ethtool_rx "$IFACE")"
  read -r S1_TP S1_PE S1_MF S1_NIP S1_FP S1_FB <<<"$(read_json_last "$JSONL")"
  gro_restore_defaults
  compare_deltas "tcpreplay" \
    "$R0_PKT" "$R0_BYT" "$R1_PKT" "$R1_BYT" \
    "$S0_TP" "$S0_PE" "$S0_MF" "$S0_NIP" "$S0_FP" "$S0_FB" \
    "$S1_TP" "$S1_PE" "$S1_MF" "$S1_NIP" "$S1_FP" "$S1_FB"
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
