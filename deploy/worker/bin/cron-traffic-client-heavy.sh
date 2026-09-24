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

# Client×service and client×country read a whole hour of flows_raw: 13–45s
# each on m61. Inside the minute tick they got ~30s after the minute jobs and
# timed out two times in three, so catch-up crawled at a few hours per hour.
export TRAFFIC_ROLLUP_LIVE_WALL_SEC="${TRAFFIC_CLIENT_HEAVY_LIVE_WALL_SEC:-240}"

exec timeout -k 10 "${TRAFFIC_CLIENT_HEAVY_TIMEOUT_SEC:-270}" \
  python3 /app/scripts/traffic_rollup_async.py \
  --jobs traffic_client_country_1h,traffic_client_service_1h,traffic_client_country_1d,traffic_client_service_1d
