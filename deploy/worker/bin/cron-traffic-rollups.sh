#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

export TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT="${TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT:-clickhouse-client}"

exec python3 /app/scripts/traffic_rollup_async.py \
  --jobs traffic_dashboard_1m,traffic_protocol_1m,traffic_direction_1m,traffic_role_1m,traffic_entity_1m,traffic_vlan_1m,traffic_country_1m,traffic_service_1m,traffic_unknown_port_1m,traffic_dashboard_1h,traffic_dashboard_1d
