#!/usr/bin/env bash
# verify_sel_native_xdp.sh — post-cutover checks for sel mlx5 native XDP.
#
# Usage (root on sel):
#   IFACE=enp4s0np0 WINDOW_SEC=60 ./scripts/verify_sel_native_xdp.sh

set -euo pipefail

IFACE="${IFACE:-enp4s0np0}"
WINDOW_SEC="${WINDOW_SEC:-60}"
ENV_FILE="${ENV_FILE:-/etc/xdpflowd/sel.env}"
SOURCE_ID="${SOURCE_ID:-xdp-sel}"
XDP_UNIT="${XDP_UNIT:-xdpflowd}"

fail=0
ok() { echo "OK   $*"; }
bad() { echo "FAIL $*"; fail=1; }
warn() { echo "WARN $*"; }

[[ "${EUID:-}" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi
XDP_MODE="${XDP_MODE:-native}"

echo "=== xdpflowd / XDP attach ==="
if systemctl is-active --quiet "$XDP_UNIT"; then
  ok "systemctl $XDP_UNIT active"
else
  bad "systemctl $XDP_UNIT not active"
fi

xdp_line="$(ip -details link show dev "$IFACE" 2>/dev/null | tr '\n' ' ' || true)"
if echo "$xdp_line" | grep -qi 'prog/xdp'; then
  ok "XDP program attached on $IFACE"
else
  bad "no XDP program on $IFACE"
fi

if journalctl -u "$XDP_UNIT" -n 30 --no-pager 2>/dev/null | grep -q "mode=$XDP_MODE"; then
  ok "journal shows mode=$XDP_MODE"
elif journalctl -u "$XDP_UNIT" -n 30 --no-pager 2>/dev/null | grep -qi "native"; then
  ok "journal mentions native mode"
else
  warn "could not confirm mode=$XDP_MODE in recent journal (check manually)"
fi

echo ""
echo "=== legacy goflow2 stopped ==="
if command -v docker >/dev/null 2>&1; then
  if docker ps --format '{{.Names}}' | grep -qx 'kcg-goflow2-1'; then
    bad "kcg-goflow2-1 still running"
  else
    ok "kcg-goflow2-1 not running"
  fi
fi

echo ""
echo "=== NIC counters (${WINDOW_SEC}s) ==="
read_counters() {
  ethtool -S "$IFACE" 2>/dev/null | awk -F': ' '
    /rx_packets_phy|rx_discards_phy|rx_prio0_discards/ {
      gsub(/^[ \t]+/, "", $1)
      gsub(/^[ \t]+|[ \t]+$/, "", $2)
      printf "%s=%.0f\n", $1, $2 + 0
    }'
  ethtool -S "$IFACE" 2>/dev/null | awk '
    /^[[:space:]]*rx[0-9]+_xdp_drop:/ {
      gsub(/:/, "", $2)
      sum += $2 + 0
    }
    END { printf "rxN_xdp_drop_sum=%.0f\n", sum + 0 }'
}

t0="$(read_counters)"
sleep "$WINDOW_SEC"
t1="$(read_counters)"

phy0="$(echo "$t0" | awk -F= '/rx_packets_phy/{print $2}')"
phy1="$(echo "$t1" | awk -F= '/rx_packets_phy/{print $2}')"
dis0="$(echo "$t0" | awk -F= '/rx_prio0_discards/{print $2}')"
dis1="$(echo "$t1" | awk -F= '/rx_prio0_discards/{print $2}')"
xdp0="$(echo "$t0" | awk -F= '/rxN_xdp_drop_sum/{print $2}')"
xdp1="$(echo "$t1" | awk -F= '/rxN_xdp_drop_sum/{print $2}')"

read -r phy_pps dis_pps xdp_pps <<EOF
$(awk -v phy0="${phy0:-0}" -v phy1="${phy1:-0}" \
      -v dis0="${dis0:-0}" -v dis1="${dis1:-0}" \
      -v xdp0="${xdp0:-0}" -v xdp1="${xdp1:-0}" \
      -v w="$WINDOW_SEC" 'BEGIN {
  phy_d = phy1 - phy0; if (phy_d < 0) phy_d = 0
  dis_d = dis1 - dis0; if (dis_d < 0) dis_d = 0
  xdp_d = xdp1 - xdp0; if (xdp_d < 0) xdp_d = 0
  if (w <= 0) w = 1
  printf "%.0f %.0f %.0f", phy_d / w, dis_d / w, xdp_d / w
}')
EOF

echo "rx_packets_phy   ${phy_pps}/s"
echo "rx_prio0_discards ${dis_pps}/s"
echo "sum(rxN_xdp_drop) ${xdp_pps}/s"

if [[ "$phy_pps" -gt 0 ]]; then
  drop_pct="$(awk -v d="$dis_pps" -v p="$phy_pps" 'BEGIN { printf "%.2f", (d/p)*100 }')"
  echo "prio0/phy ratio: ${drop_pct}% (informational on mlx5; see docs/SEL_CONNECTX4_CAPTURE_LIMITS.md)"
  ok "PHY counters sampled"
else
  warn "no rx_packets_phy growth — mirror quiet or wrong IFACE?"
fi

if [[ "$XDP_MODE" == "native" && "${XDP_ACTION:-drop}" == "drop" ]]; then
  if [[ "$xdp_pps" -gt 1000 ]]; then
    ok "XDP drop counters growing (${xdp_pps}/s)"
  elif [[ "$phy_pps" -gt 10000 ]]; then
    bad "PHY traffic high but rxN_xdp_drop too low (${xdp_pps}/s)"
  else
    warn "could not confirm XDP traffic (quiet mirror?)"
  fi
fi

echo ""
echo "=== xdpflowd stats (journal, last ${WINDOW_SEC}s window) ==="
stats="$(journalctl -u "$XDP_UNIT" --since "${WINDOW_SEC} seconds ago" --no-pager 2>/dev/null | grep 'msg=stats' | tail -1 || true)"
if [[ -n "$stats" ]]; then
  echo "$stats"
  ok "stats line present"
else
  warn "no msg=stats in last ${WINDOW_SEC}s — wait and re-check: journalctl -u $XDP_UNIT -f"
fi

spool="$(journalctl -u "$XDP_UNIT" --since "${WINDOW_SEC} seconds ago" --no-pager 2>/dev/null | grep 'clickhouse spool pipeline' | tail -1 || true)"
if [[ -n "$spool" ]]; then
  echo "$spool"
  if echo "$spool" | grep -q 'insert_errs=0'; then
    ok "ClickHouse insert_errs=0"
  else
    bad "ClickHouse insert errors in spool line"
  fi
fi

echo ""
echo "=== ClickHouse ingest (optional) ==="
if command -v clickhouse-client >/dev/null 2>&1 && [[ -n "${XDP_CH_DSN:-}" ]]; then
  # Parse host/port/user from DSN best-effort; fall back to m61 defaults.
  CH_HOST="${CH_HOST:-95.215.1.30}"
  CH_PORT="${CH_PORT:-6124}"
  CH_USER="${CH_USER:-develop}"
  rows="$(clickhouse-client --host "$CH_HOST" --port "$CH_PORT" --user "$CH_USER" --query "
    SELECT count() FROM default.flows_raw
    WHERE source_id = '$SOURCE_ID'
      AND IPv4NumToString(toIPv4(reinterpretAsUInt32(reverse(substring(sampler_address,1,4))))) = '${XDP_CH_SAMPLER_ADDR:-95.215.0.26}'
      AND time_received_ns >= now64(9) - INTERVAL ${WINDOW_SEC} SECOND
  " 2>/dev/null || echo "")"
  if [[ -n "$rows" && "$rows" -gt 0 ]]; then
    ok "ClickHouse rows last ${WINDOW_SEC}s: $rows (source_id=$SOURCE_ID)"
  else
    warn "ClickHouse query failed or 0 rows (check DSN / password / network)"
  fi
else
  warn "skip ClickHouse check (no clickhouse-client or XDP_CH_DSN)"
fi

echo ""
if [[ "$fail" -eq 0 ]]; then
  echo "RESULT: PASS"
  exit 0
fi
echo "RESULT: FAIL — see lines above"
exit 1
