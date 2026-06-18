#!/usr/bin/env bash
# diagnose_sel_collector.sh — root checklist on sel after cutover.
#
# Checks xdpflowd/dnsflowd, env (xdp-sel / dns-sel), NIC/XDP counters, journal
# for ClickHouse insert errors, and optional local CH ingest probe.
#
# Usage (root on sel):
#   cd /root/GrapesNTA && ./scripts/diagnose_sel_collector.sh
#   WINDOW_SEC=120 ./scripts/diagnose_sel_collector.sh

set -euo pipefail

IFACE="${IFACE:-enp4s0np0}"
WINDOW_SEC="${WINDOW_SEC:-60}"
XDP_ENV="${XDP_ENV:-/etc/xdpflowd/sel.env}"
DNS_ENV="${DNS_ENV:-/etc/dnsflowd/sel.env}"
XDP_UNIT="${XDP_UNIT:-xdpflowd}"
DNS_UNIT="${DNS_UNIT:-dnsflowd}"
EXPECTED_SOURCE_ID="${EXPECTED_SOURCE_ID:-xdp-sel}"
EXPECTED_DNS_SOURCE_ID="${EXPECTED_DNS_SOURCE_ID:-dns-sel}"
EXPECTED_SAMPLER="${EXPECTED_SAMPLER:-95.215.0.26}"

fail=0
warn=0
ok() { echo "OK   $*"; }
bad() { echo "FAIL $*"; fail=1; }
maybe() { echo "WARN $*"; warn=1; }

[[ "${EUID:-}" -eq 0 ]] || { echo "Run as root on sel." >&2; exit 1; }

short="$(hostname -s 2>/dev/null || hostname | cut -d. -f1)"
echo "=== sel collector diagnose ($(date -Is)) host=$short ==="
echo ""

echo "=== 1. Env files ==="
for f in "$XDP_ENV" "$DNS_ENV"; do
  if [[ -r "$f" ]]; then
    ok "readable $f"
  else
    bad "missing or unreadable $f"
    continue
  fi
done

if [[ -r "$XDP_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$XDP_ENV"
  for kv in \
    "REPO_ROOT=${REPO_ROOT:-}" \
    "IFACE=${IFACE:-}" \
    "XDP_MODE=${XDP_MODE:-}" \
    "XDPFLOWD_SOURCE_ID=${XDPFLOWD_SOURCE_ID:-}" \
    "XDP_CH_SAMPLER_ADDR=${XDP_CH_SAMPLER_ADDR:-}" \
    "XDP_CH_TABLE=${XDP_CH_TABLE:-default.flows_raw}" \
    "XDP_DNS_PASSTHROUGH=${XDP_DNS_PASSTHROUGH:-}"; do
    echo "     $kv"
  done
  [[ -n "${XDP_CH_DSN:-}" ]] && ok "XDP_CH_DSN set" || bad "XDP_CH_DSN empty"
  [[ "${XDPFLOWD_SOURCE_ID:-}" == "$EXPECTED_SOURCE_ID" ]] \
    && ok "XDPFLOWD_SOURCE_ID=$EXPECTED_SOURCE_ID" \
    || bad "XDPFLOWD_SOURCE_ID=${XDPFLOWD_SOURCE_ID:-<unset>} (expected $EXPECTED_SOURCE_ID)"
  [[ "${XDP_CH_SAMPLER_ADDR:-}" == "$EXPECTED_SAMPLER" ]] \
    && ok "sampler $EXPECTED_SAMPLER" \
    || maybe "XDP_CH_SAMPLER_ADDR=${XDP_CH_SAMPLER_ADDR:-<unset>} (expected $EXPECTED_SAMPLER)"
  [[ "${XDP_DNS_PASSTHROUGH:-0}" == "1" ]] \
    && ok "XDP_DNS_PASSTHROUGH=1 (dnsflowd can capture UDP/53)" \
    || bad "XDP_DNS_PASSTHROUGH=${XDP_DNS_PASSTHROUGH:-0} — dnsflowd needs 1 on shared mirror"
  [[ "${IFACE:-}" == "$IFACE" ]] || maybe "env IFACE=${IFACE:-} differs from script IFACE=$IFACE"
fi

if [[ -r "$DNS_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$DNS_ENV"
  echo "     DNSFLOWD_SOURCE_ID=${DNSFLOWD_SOURCE_ID:-}"
  [[ "${DNSFLOWD_SOURCE_ID:-}" == "$EXPECTED_DNS_SOURCE_ID" ]] \
    && ok "DNSFLOWD_SOURCE_ID=$EXPECTED_DNS_SOURCE_ID" \
    || bad "DNSFLOWD_SOURCE_ID=${DNSFLOWD_SOURCE_ID:-<unset>} (expected $EXPECTED_DNS_SOURCE_ID)"
  [[ -n "${DNS_CH_DSN:-}" ]] && ok "DNS_CH_DSN set" || bad "DNS_CH_DSN empty"
fi

echo ""
echo "=== 2. systemd ==="
for unit in "$XDP_UNIT" "$DNS_UNIT"; do
  if systemctl is-active --quiet "$unit"; then
    ok "systemctl $unit active"
  else
    bad "systemctl $unit not active — run: systemctl status $unit -l --no-pager"
  fi
done

echo ""
echo "=== 3. XDP attach on $IFACE ==="
xdp_line="$(ip -details link show dev "$IFACE" 2>/dev/null | tr '\n' ' ' || true)"
if echo "$xdp_line" | grep -qi 'prog/xdp'; then
  ok "XDP program attached"
else
  bad "no XDP on $IFACE — check IFACE in $XDP_ENV"
fi

echo ""
echo "=== 4. Legacy goflow2 stopped ==="
if command -v docker >/dev/null 2>&1; then
  if docker ps --format '{{.Names}}' | grep -qx 'kcg-goflow2-1'; then
    bad "kcg-goflow2-1 still running (duplicate netflow path)"
  else
    ok "kcg-goflow2-1 not running"
  fi
fi

echo ""
echo "=== 5. NIC counters (${WINDOW_SEC}s) ==="
read_counters() {
  ethtool -S "$IFACE" 2>/dev/null | awk -F': ' '
    /rx_packets_phy|rx_discards_phy|rx_prio0_discards/ {gsub(/^[ \t]+/,"",$1); print $1"="$2}'
  local sum
  sum="$(ethtool -S "$IFACE" 2>/dev/null | awk '
    /^[[:space:]]*rx[0-9]+_xdp_drop:/ { gsub(/:/, "", $2); sum += $2 }
    END { print sum + 0 }')"
  echo "rxN_xdp_drop_sum=$sum"
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

phy_d=$((phy1 - phy0))
dis_d=$((dis1 - dis0))
xdp_d=$((xdp1 - xdp0))
phy_pps=$((phy_d / WINDOW_SEC))
dis_pps=$((dis_d / WINDOW_SEC))
xdp_pps=$((xdp_d / WINDOW_SEC))

echo "rx_packets_phy    ${phy_pps}/s"
echo "rx_prio0_discards ${dis_pps}/s"
echo "sum(rxN_xdp_drop) ${xdp_pps}/s"

if [[ "$phy_pps" -gt 0 ]]; then
  drop_pct="$(awk -v d="$dis_pps" -v p="$phy_pps" 'BEGIN { printf "%.4f", (d/p)*100 }')"
  echo "prio0 drop ratio: ${drop_pct}%"
  if awk -v r="$drop_pct" 'BEGIN { exit !(r > 1.0) }'; then
    bad "rx_prio0_discards > 1% of phy"
  else
    ok "PHY drop ratio acceptable"
  fi
else
  maybe "no rx_packets_phy growth — mirror quiet or wrong IFACE?"
fi

if [[ "${XDP_MODE:-native}" == "native" && "${XDP_ACTION:-drop}" == "drop" ]]; then
  if [[ "$xdp_pps" -gt 1000 ]]; then
    ok "native XDP drop counters growing (${xdp_pps}/s)"
  else
    bad "native rxN_xdp_drop too low (${xdp_pps}/s) — XDP may not see traffic"
  fi
fi

echo ""
echo "=== 6. xdpflowd journal (last ${WINDOW_SEC}s) ==="
stats="$(journalctl -u "$XDP_UNIT" --since "${WINDOW_SEC} seconds ago" --no-pager 2>/dev/null | grep 'msg=stats' | tail -1 || true)"
if [[ -n "$stats" ]]; then
  echo "$stats"
  ok "stats line present"
else
  maybe "no msg=stats — journalctl -u $XDP_UNIT -f"
fi

spool="$(journalctl -u "$XDP_UNIT" --since "${WINDOW_SEC} seconds ago" --no-pager 2>/dev/null | grep 'clickhouse spool pipeline' | tail -1 || true)"
if [[ -n "$spool" ]]; then
  echo "$spool"
  if echo "$spool" | grep -q 'insert_errs=0'; then
    ok "ClickHouse insert_errs=0"
  else
    bad "ClickHouse insert errors in spool line"
  fi
else
  maybe "no clickhouse spool pipeline line in last ${WINDOW_SEC}s"
fi

if journalctl -u "$XDP_UNIT" --since "10 minutes ago" --no-pager 2>/dev/null | grep -qi 'flow loss'; then
  bad "xdpflowd flow loss alerts in last 10m"
else
  ok "no flow loss alerts in last 10m"
fi

if journalctl -u "$XDP_UNIT" --since "10 minutes ago" --no-pager 2>/dev/null | grep -qi 'stale source_id'; then
  bad "stale source_id rows skipped — restart xdpflowd after changing XDPFLOWD_SOURCE_ID"
else
  ok "no stale source_id warnings"
fi

echo ""
echo "=== 7. dnsflowd journal (last ${WINDOW_SEC}s) ==="
dns_stats="$(journalctl -u "$DNS_UNIT" --since "${WINDOW_SEC} seconds ago" --no-pager 2>/dev/null | grep -E 'msg=stats|insert_errs' | tail -3 || true)"
if [[ -n "$dns_stats" ]]; then
  echo "$dns_stats"
  if echo "$dns_stats" | grep -q 'insert_errs=0'; then
    ok "dnsflowd insert_errs=0"
  elif echo "$dns_stats" | grep -q 'insert_errs='; then
    bad "dnsflowd ClickHouse insert errors"
  else
    ok "dnsflowd logging"
  fi
else
  maybe "no dnsflowd stats in last ${WINDOW_SEC}s"
fi

echo ""
echo "=== 8. ClickHouse ingest probe (optional) ==="
if command -v clickhouse-client >/dev/null 2>&1 && [[ -n "${XDP_CH_DSN:-}" ]]; then
  CH_HOST="${CH_HOST:-95.215.1.30}"
  CH_PORT="${CH_PORT:-6124}"
  CH_USER="${CH_USER:-develop}"
  CH_PASS="${CH_PASS:-}"

  flow_rows="$(clickhouse-client --host "$CH_HOST" --port "$CH_PORT" --user "$CH_USER" ${CH_PASS:+--password "$CH_PASS"} --query "
    SELECT count()
    FROM default.flows_raw
    WHERE source_id = '$EXPECTED_SOURCE_ID'
      AND time_flow_start_ns >= now64(9) - INTERVAL ${WINDOW_SEC} SECOND
  " 2>/dev/null || echo "")"

  dns_rows="$(clickhouse-client --host "$CH_HOST" --port "$CH_PORT" --user "$CH_USER" ${CH_PASS:+--password "$CH_PASS"} --query "
    SELECT count()
    FROM default.dns_log
    WHERE source_id = '$EXPECTED_DNS_SOURCE_ID'
      AND ts >= now64(6) - INTERVAL ${WINDOW_SEC} SECOND
  " 2>/dev/null || echo "")"

  if [[ -n "$flow_rows" && "$flow_rows" -gt 0 ]]; then
    ok "flows_raw $EXPECTED_SOURCE_ID last ${WINDOW_SEC}s: $flow_rows rows"
  else
    bad "flows_raw $EXPECTED_SOURCE_ID: 0 rows in last ${WINDOW_SEC}s (or CH query failed)"
    echo "     Fix: confirm XDPFLOWD_SOURCE_ID, restart xdpflowd, check XDP_CH_DSN"
    echo "     Remote check: ./scripts/monitor_sel_collector_ch.sh"
  fi

  if [[ -n "$dns_rows" && "$dns_rows" -gt 0 ]]; then
    ok "dns_log $EXPECTED_DNS_SOURCE_ID last ${WINDOW_SEC}s: $dns_rows rows"
  else
    bad "dns_log $EXPECTED_DNS_SOURCE_ID: 0 rows in last ${WINDOW_SEC}s"
  fi

  wrong="$(clickhouse-client --host "$CH_HOST" --port "$CH_PORT" --user "$CH_USER" ${CH_PASS:+--password "$CH_PASS"} --query "
    SELECT count()
    FROM default.flows_raw
    WHERE source_id IN ('xdp-default', 'netflow')
      AND IPv6NumToString(sampler_address) LIKE '5fd7:1a%'
      AND time_flow_start_ns >= now64(9) - INTERVAL ${WINDOW_SEC} SECOND
  " 2>/dev/null || echo "")"
  if [[ -n "$wrong" && "$wrong" -gt 0 ]]; then
    maybe "legacy source_id (xdp-default/netflow) still writing with sel sampler ($wrong rows) — wrong binary or env"
  fi
else
  maybe "skip CH probe (install clickhouse-client or set CH_USER/CH_PASS; or run monitor_sel_collector_ch.sh from workstation)"
fi

echo ""
echo "=== 9. Quick remediation ==="
echo "  # wrong source_id / after env change:"
echo "  systemctl restart $XDP_UNIT"
echo "  # full sel setup:"
echo "  cd /root/GrapesNTA && ./scripts/prod_setup_sel_collector.sh"
echo "  # re-cutover XDP:"
echo "  cd /root/GrapesNTA && XDP_ALLOW_NO_NETFLOW_RULE=1 ./scripts/prod_enable_xdpflowd_sel.sh"
echo "  # live logs:"
echo "  journalctl -u $XDP_UNIT -f"
echo "  journalctl -u $DNS_UNIT -f"

echo ""
if [[ "$fail" -eq 0 ]]; then
  echo "RESULT: PASS (warnings: $warn)"
  exit 0
fi
echo "RESULT: FAIL (warnings: $warn) — see FAIL/WARN lines above"
exit 1
