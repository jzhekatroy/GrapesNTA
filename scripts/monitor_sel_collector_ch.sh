#!/usr/bin/env bash
# monitor_sel_collector_ch.sh — ClickHouse ingest health for sel collector.
#
# Run from any host with curl access to ClickHouse HTTP port.
#
# Usage:
#   CH_URL=http://95.215.1.30:6123 CH_USER=ui_read CH_PASS=... ./scripts/monitor_sel_collector_ch.sh
#   ./scripts/monitor_sel_collector_ch.sh   # reads NTAdmin .env if present

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NTADMIN_ENV="${NTADMIN_ENV:-/Users/evgenijtroanov/NTAdmin/.env}"
if [[ ! -r "$NTADMIN_ENV" ]]; then
  NTADMIN_ENV="${NTADMIN_ENV:-$HOME/NTAdmin/.env}"
fi

if [[ -z "${CH_URL:-}" && -r "$NTADMIN_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$NTADMIN_ENV"
  CH_URL="${CLICKHOUSE_URL:-http://95.215.1.30:6123}"
  CH_USER="${CLICKHOUSE_READ_USER:-ui_read}"
  CH_PASS="${CLICKHOUSE_READ_PASSWORD:-}"
  CH_DB="${CLICKHOUSE_DATABASE:-default}"
fi

CH_URL="${CH_URL:-http://95.215.1.30:6123}"
CH_USER="${CH_USER:-ui_read}"
CH_PASS="${CH_PASS:-}"
CH_DB="${CH_DB:-default}"
WINDOW_MIN="${WINDOW_MIN:-5}"

if [[ -z "$CH_PASS" ]]; then
  echo "Set CH_PASS or CLICKHOUSE_READ_PASSWORD (or point NTADMIN_ENV to .env)" >&2
  exit 1
fi

q() {
  curl -sS -m 120 -u "${CH_USER}:${CH_PASS}" \
    "${CH_URL}/?database=${CH_DB}" \
    --data-binary "$1"
}

section() { echo ""; echo "=== $* ==="; }

section "ClickHouse time"
q "SELECT now64(9) AS now_utc, timezone() AS tz FORMAT TabSeparated"

section "Ingest health (alert rows — empty = OK)"
q "
SELECT *
FROM (
    SELECT
        'flows_xdp_sel_stale' AS alert,
        source_id,
        dateDiff('second', max(time_flow_start_ns), now64(9)) AS age_sec,
        count() AS rows_${WINDOW_MIN}m
    FROM default.flows_raw
    WHERE source_id = 'xdp-sel'
      AND time_flow_start_ns >= now64(9) - INTERVAL ${WINDOW_MIN} MINUTE
    GROUP BY source_id
    HAVING age_sec > 120 OR rows_${WINDOW_MIN}m = 0

    UNION ALL

    SELECT
        'flows_netflow_stale' AS alert,
        source_id,
        dateDiff('second', max(time_flow_start_ns), now64(9)) AS age_sec,
        count() AS rows_${WINDOW_MIN}m
    FROM default.flows_raw
    WHERE source_id = 'netflow'
      AND time_flow_start_ns >= now64(9) - INTERVAL ${WINDOW_MIN} MINUTE
    GROUP BY source_id
    HAVING age_sec > 120 OR rows_${WINDOW_MIN}m = 0

    UNION ALL

    SELECT
        'dns_sel_stale' AS alert,
        source_id,
        dateDiff('second', max(ts), now64(6)) AS age_sec,
        count() AS rows_${WINDOW_MIN}m
    FROM default.dns_log
    WHERE source_id = 'dns-sel'
      AND ts >= now64(6) - INTERVAL ${WINDOW_MIN} MINUTE
    GROUP BY source_id
    HAVING age_sec > 30 OR rows_${WINDOW_MIN}m = 0

    UNION ALL

    SELECT
        'xdp_sel_never_ingested' AS alert,
        'xdp-sel' AS source_id,
        toInt64(0) AS age_sec,
        count() AS rows_${WINDOW_MIN}m
    FROM default.flows_raw
    WHERE source_id = 'xdp-sel'
    HAVING rows_${WINDOW_MIN}m = 0
)
FORMAT PrettyCompact
"

section "Volume last ${WINDOW_MIN} min — flows (xdp-sel, netflow, xdp-default)"
q "
SELECT
    source_id,
    count() AS rows,
    round(sum(bytes) / 1024 / 1024, 2) AS sum_mb,
    round(sum(bytes) / dateDiff('second', min(time_flow_start_ns), max(time_flow_start_ns)) / 1024 / 1024, 3) AS mb_per_sec,
    round(count() / dateDiff('second', min(time_flow_start_ns), max(time_flow_start_ns)) * 60, 0) AS flows_per_min,
    round(sum(bytes) / dateDiff('second', min(time_flow_start_ns), max(time_flow_start_ns)) * 86400 / 1024 / 1024 / 1024, 1) AS gb_per_day_est,
    dateDiff('second', max(time_flow_start_ns), now64(9)) AS flow_age_sec,
    dateDiff('second', max(time_received_ns), now64(9)) AS recv_age_sec,
    quantile(0.95)(dateDiff('second', time_flow_start_ns, time_received_ns)) AS p95_lag_sec
FROM default.flows_raw
WHERE time_flow_start_ns >= now64(9) - INTERVAL ${WINDOW_MIN} MINUTE
  AND source_id IN ('xdp-sel', 'netflow', 'xdp-default')
GROUP BY source_id
ORDER BY source_id
FORMAT PrettyCompact
"

section "Volume last ${WINDOW_MIN} min — DNS (dns-sel vs dns-netflow)"
q "
SELECT
    source_id,
    count() AS rows,
    round(sum(raw_size) / 1024 / 1024, 2) AS sum_mb,
    round(sum(raw_size) / dateDiff('second', min(ts), max(ts)) / 1024 / 1024, 3) AS mb_per_sec,
    round(count() / dateDiff('second', min(ts), max(ts)) * 60, 0) AS rows_per_min,
    round(sum(raw_size) / dateDiff('second', min(ts), max(ts)) * 86400 / 1024 / 1024 / 1024, 1) AS gb_per_day_est,
    dateDiff('second', max(ts), now64(6)) AS ts_age_sec,
    uniqExact(IPv6NumToString(sampler_address)) AS samplers
FROM default.dns_log
WHERE ts >= now64(6) - INTERVAL ${WINDOW_MIN} MINUTE
  AND source_id IN ('dns-sel', 'dns-netflow')
GROUP BY source_id
ORDER BY source_id
FORMAT PrettyCompact
"

section "Sampler map (flows, last 24h)"
q "
SELECT
    source_id,
    IPv6NumToString(sampler_address) AS sampler,
    count() AS rows,
    max(time_flow_start_ns) AS max_flow
FROM default.flows_raw
WHERE time_flow_start_ns >= now64(9) - INTERVAL 24 HOUR
  AND source_id IN ('xdp-sel', 'netflow', 'xdp-default')
GROUP BY source_id, sampler
ORDER BY rows DESC
LIMIT 20
FORMAT PrettyCompact
"

section "Catalog bindings"
q "
SELECT source_id, collector_id, enabled, include_in_total
FROM default.net_flow_sources
WHERE source_id IN ('xdp-sel', 'dns-sel', 'netflow', 'dns-netflow', 'xdp-default')
ORDER BY source_id
FORMAT PrettyCompact
" 2>/dev/null || echo "(net_flow_sources not readable with this user)"

echo ""
