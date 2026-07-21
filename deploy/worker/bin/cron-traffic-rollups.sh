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

exec python3 /app/scripts/traffic_rollup_async.py \
  --jobs traffic_dashboard_1m,traffic_protocol_1m,traffic_direction_1m,traffic_role_1m,traffic_entity_1m,traffic_vlan_1m,traffic_country_1m,traffic_service_1m,traffic_unknown_port_1m,traffic_dashboard_1h,traffic_dashboard_1d
