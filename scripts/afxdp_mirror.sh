#!/usr/bin/env bash
# afxdp_mirror.sh — copy ingress of SRC_IFACE to a dedicated veth; run afxdpflowd on the mirror (option 2).
#
# L3/SSH/iperf on SRC_IFACE (e.g. veth0) keep working. Duplicates are injected into
# veth-afx0 RX; afxdpflowd attaches there and only "steals" the copy, not the path to the stack.
#
# Requires: root, tc (iproute2), act_mirred (modprobe if needed), kernel with ingress + mirred.
#
# Usage:
#   sudo ./scripts/afxdp_mirror.sh up [SRC_IFACE]     # default SRC_IFACE=veth0
#   sudo ./scripts/afxdp_mirror.sh down [SRC_IFACE]   # remove mirror + veth-afx*
#   sudo ./scripts/afxdp_mirror.sh show
#
# After `up`, start collector + daemon (separate terminals):
#   sudo mkdir -p /tmp/nfcap_afx
#   sudo nfcapd -b 127.0.0.1 -p 2056 -w /tmp/nfcap_afx -I afx -t 60 -e
#   cd /path/to/GrapesNTA && sudo timeout 90 ./bin/afxdpflowd -iface veth-afx0 -skb \
#     -nf-dst 127.0.0.1:2056 -nf-active 15s -nf-idle 5s -stats 5s
# Traffic still runs on veth0 + testns; veth-afx0 only gets the mirror.
#
# If mirror fails, try: sudo ethtool -K "$SRC" gro off  (on SRC only; optional)

set -euo pipefail

MIR="veth-afx0"
PEER="veth-afx1"
TC_PRIO=100
TC_PREF="${TC_PREF:-100}"

need_root() {
  if [[ "${EUID:-}" -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
  fi
}

mod_ingress() {
  modprobe ifb 2>/dev/null || true
  modprobe act_mirred 2>/dev/null || true
}

qdisc_ingress_exists() {
  local dev=$1
  tc qdisc show dev "$dev" 2>/dev/null | grep -qE 'qdisc ingress|qdisc ffff:'
}

up() {
  need_root
  mod_ingress
  local src="${1:-veth0}"
  if ! ip link show "$src" &>/dev/null; then
    echo "Interface $src does not exist" >&2
    exit 1
  fi
  # Remove old mirror state if re-running
  if ip link show "$MIR" &>/dev/null; then
    down "$src" || true
  fi
  ip link add "$MIR" type veth peer name "$PEER" 2>/dev/null || {
    echo "Create veth: $MIR exists? Run: $0 down $src" >&2
    exit 1
  }
  ip link set "$MIR" up
  ip link set "$PEER" up
  if ! qdisc_ingress_exists "$src"; then
    tc qdisc add dev "$src" handle ffff: ingress
  fi
  # Duplicate all ingress; original still goes to stack (mirred mirror, not redirect).
  if tc filter show dev "$src" parent ffff: 2>/dev/null | grep -qE "match.*mirred|mirred.*$MIR"; then
    echo "Filter may already exist; add skipped (run 'down' first to reset)." >&2
  else
    if ! tc filter add dev "$src" parent ffff: protocol all prio "$TC_PREF" u32 \
      match u32 0 0 \
      action mirred egress mirror dev "$MIR"; then
      echo "tc filter failed (older iproute2?). Try: ethtool -K $src gro off" >&2
      ip link del "$MIR" 2>/dev/null || true
      exit 1
    fi
  fi
  echo "OK: mirror $src ingress -> $MIR (AF_XDP + NetFlow on $MIR; keep using $src for L3/iperf)."
  echo "  afxdpflowd:  -iface $MIR  (not $src)"
  ip -br link show "$MIR" "$PEER" 2>/dev/null || true
}

down() {
  need_root
  local src="${1:-veth0}"
  if qdisc_ingress_exists "$src"; then
    tc filter del dev "$src" parent ffff: prio "$TC_PREF" 2>/dev/null || \
    tc filter del dev "$src" parent ffff: protocol all prio "$TC_PREF" 2>/dev/null || true
    # if no filters left, optional: remove ingress qdisc
    if ! tc filter show dev "$src" parent ffff: 2>/dev/null | grep -qE 'filter|u32|match|mirred|flower'; then
      tc qdisc del dev "$src" handle ffff: ingress 2>/dev/null || true
    fi
  fi
  if ip link show "$MIR" &>/dev/null; then
    ip link del "$MIR" 2>/dev/null || true
  fi
  echo "OK: removed mirror on $src and veth $MIR/$PEER (if any)."
}

show() {
  local src="${1:-veth0}"
  echo "--- tc qdisc $src ---"
  tc qdisc show dev "$src" 2>/dev/null || true
  echo "--- tc filter parent ffff: $src ---"
  tc filter show dev "$src" parent ffff: 2>/dev/null || true
  echo "--- ip -br (mirror veth) ---"
  ip -br link show 2>/dev/null | grep -E "veth-afx|${src}" || true
}

cmd="${1:-}"
case "$cmd" in
  up)   shift; up "$@" ;;
  down) shift; down "$@" ;;
  show) shift; show "$@" ;;
  *)
    echo "Usage: $0 {up|down|show} [SRC_IFACE, default: veth0]" >&2
    exit 2
    ;;
esac
