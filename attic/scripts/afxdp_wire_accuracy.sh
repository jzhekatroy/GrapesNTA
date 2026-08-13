#!/usr/bin/env bash
# Compare AF_XDP wire_ground_truth counters vs sysfs rx_* (same idea as accuracy_test.sh for xdpflowd).
#
# Env:
#   IFACE          — interface (default: ens18)
#   AFXDP_BIN      — path to afxdpflowd (default: ./bin/afxdpflowd)
#   DURATION_SEC   — how long to run afxdpflowd (default: 15)
#   IPERF3_HOST    — if set, run iperf3 -R after afxdp starts (same as accuracy_test)
#
set -euo pipefail

IFACE="${IFACE:-ens18}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
AFXDP_BIN="${AFXDP_BIN:-$ROOT/bin/afxdpflowd}"
DURATION_SEC="${DURATION_SEC:-15}"
LOG="${TMPDIR:-/tmp}/afxdp_wire_accuracy.log"
THRESH_PKTS="${THRESH_PKTS:-99.50}"

need_root() {
  if [[ "${EUID:-}" -ne 0 ]]; then
    echo "Run as root (XDP + sysfs)." >&2
    exit 1
  fi
}

ethtool_rx() {
  local iface="$1"
  local p="/sys/class/net/$iface/statistics"
  echo "$(cat "$p/rx_packets" 2>/dev/null || echo 0) $(cat "$p/rx_bytes" 2>/dev/null || echo 0)"
}

read_wire_pkts() {
  # Last JSON line: .wire_ground_truth.packets
  local f="$1"
  [[ -f "$f" ]] || { echo 0; return; }
  tail -n 1 "$f" 2>/dev/null | jq -r '.wire_ground_truth.packets // 0' 2>/dev/null || echo 0
}

read_wire_bytes() {
  local f="$1"
  [[ -f "$f" ]] || { echo 0; return; }
  tail -n 1 "$f" 2>/dev/null | jq -r '.wire_ground_truth.bytes // 0' 2>/dev/null || echo 0
}

ensure_running() {
  local pid="$1"
  if kill -0 "$pid" 2>/dev/null; then
    return 0
  fi

  local rc=0
  wait "$pid" || rc=$?
  echo "FAIL: afxdpflowd exited before measurement window (exit=$rc)." >&2
  if [[ -s "$LOG" ]]; then
    echo "--- afxdpflowd log ---" >&2
    sed -n '1,120p' "$LOG" >&2
  fi
  exit 1
}

main() {
  need_root
  command -v jq >/dev/null || { echo "Install jq"; exit 1; }
  [[ -x "$AFXDP_BIN" ]] || { echo "Build afxdpflowd first: make -C $ROOT build-afxdp"; exit 1; }

  : >"$LOG"
  # stderr JSON lines; try native XDP first.
  set +e
  "$AFXDP_BIN" -iface "$IFACE" -stats 1s 2> >(tee -a "$LOG" >&2) &
  apid=$!
  set -e
  sleep 2
  ensure_running "$apid"

  read -r R0_PKT R0_BYT <<<"$(ethtool_rx "$IFACE")"
  W0_PK="$(read_wire_pkts "$LOG")"
  W0_BY="$(read_wire_bytes "$LOG")"

  if [[ -n "${IPERF3_HOST:-}" ]]; then
    iperf3 -c "$IPERF3_HOST" -p "${IPERF3_PORT:-5201}" -R -t "$((DURATION_SEC - 4))" -u -b 200M || true
  else
    sleep "$DURATION_SEC"
  fi

  kill -TERM "$apid" 2>/dev/null || true
  sleep 1
  kill -KILL "$apid" 2>/dev/null || true

  read -r R1_PKT R1_BYT <<<"$(ethtool_rx "$IFACE")"
  W1_PK="$(read_wire_pkts "$LOG")"
  W1_BY="$(read_wire_bytes "$LOG")"

  drx_pk=$((R1_PKT - R0_PKT))
  drx_by=$((R1_BYT - R0_BYT))
  dw_pk=$((W1_PK - W0_PK))
  dw_by=$((W1_BY - W0_BY))

  echo "=== afxdp wire vs sysfs ==="
  echo "sysfs delta:  rx_packets=$drx_pk rx_bytes=$drx_by"
  echo "wire delta:  packets=$dw_pk bytes=$dw_by  (ground truth from afxdpflowd last JSON line)"

  if [[ "$drx_pk" -le 0 ]]; then
    echo "WARN: no RX delta (wrong IFACE or no traffic?)"
    exit 0
  fi

  pct="$(awk -v a="$dw_pk" -v b="$drx_pk" 'BEGIN{printf "%.4f", (100.0 * a / b)}')"
  echo "Ratio wire_packets / sysfs_rx_packets = ${pct}% (want >= ${THRESH_PKTS}%)"
  if awk -v p="$pct" -v t="$THRESH_PKTS" 'BEGIN{ exit (p + 0 >= t + 0) ? 0 : 1 }'; then
    echo "PASS (packets)"
  else
    echo "FAIL: packet ratio below ${THRESH_PKTS}% (try -skb on VM, or single RX queue: ethtool -L ${IFACE} combined 1)"
    exit 1
  fi
}

main "$@"
