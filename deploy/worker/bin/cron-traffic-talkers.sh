#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

export TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT=/usr/local/bin/clickhouse-client
export TRAFFIC_ROLLUP_MAX_BUCKETS_PER_JOB="${TRAFFIC_TALKERS_MAX_BUCKETS_PER_JOB:-${TRAFFIC_ROLLUP_MAX_BUCKETS_PER_JOB:-15}}"
export CLICKHOUSE_HTTP_HOST="${TRAFFIC_ROLLUP_CH_HOST:-127.0.0.1}"
export CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
export CLICKHOUSE_HTTP_USER="${TRAFFIC_ROLLUP_CH_USER:-default}"
export CLICKHOUSE_HTTP_PASSWORD="${TRAFFIC_ROLLUP_CH_PASSWORD:-}"

# This cron runs every 5 minutes, so it may legitimately work longer than the
# per-minute rollups; the budget still has to stay inside its own interval.
export TRAFFIC_ROLLUP_LIVE_WALL_SEC="${TRAFFIC_TALKERS_LIVE_WALL_SEC:-240}"

exec timeout -k 10 "${TRAFFIC_TALKERS_TIMEOUT_SEC:-270}" \
  python3 /app/scripts/traffic_rollup_async.py \
  --jobs traffic_asn_1m,traffic_asn_1h,traffic_asn_pair_1m,traffic_asn_pair_1h
