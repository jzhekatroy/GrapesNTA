#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

export TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT=/usr/local/bin/clickhouse-client
export CLICKHOUSE_HTTP_HOST="${TRAFFIC_ROLLUP_CH_HOST:-127.0.0.1}"
export CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
export CLICKHOUSE_HTTP_USER="${TRAFFIC_ROLLUP_CH_USER:-default}"
export CLICKHOUSE_HTTP_PASSWORD="${TRAFFIC_ROLLUP_CH_PASSWORD:-}"

# Both steps carry their own wall budget, so these timeouts are the outer
# backstop for a hang the script itself cannot see (a wedged interpreter, a
# child that ignores its deadline). Without them a single stuck run keeps the
# flock and every later tick logs "job is still running".
QUEUE_TIMEOUT="${TRAFFIC_ROLLUP_QUEUE_TIMEOUT_SEC:-210}"
LIVE_TIMEOUT="${TRAFFIC_ROLLUP_LIVE_TIMEOUT_SEC:-55}"

# 1) Drain any diagnostics backfill request (gap fill) before live catch-up.
#    flock is held by supercronic for the whole script, so queue + live do not overlap.
timeout -k 10 "$QUEUE_TIMEOUT" python3 /app/scripts/traffic_rollup_async.py --process-queue || true

# 2) Steady-state live rollups.
# traffic_client_anomaly_1m intentionally omitted until anomaly detection exists.
exec timeout -k 10 "$LIVE_TIMEOUT" python3 /app/scripts/traffic_rollup_async.py \
  --jobs traffic_dashboard_1m,traffic_protocol_1m,traffic_direction_1m,traffic_role_1m,traffic_entity_1m,traffic_client_1m,traffic_vlan_1m,traffic_country_1m,traffic_service_1m,traffic_unknown_port_1m,traffic_dashboard_1h,traffic_client_1h,traffic_client_country_1h,traffic_client_service_1h,traffic_dashboard_1d,traffic_client_1d,traffic_client_country_1d,traffic_client_service_1d,dns_client_domain_1h
