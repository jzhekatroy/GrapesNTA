#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

export TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT="${TRAFFIC_ROLLUP_CLICKHOUSE_CLIENT:-clickhouse-client}"
export TRAFFIC_ROLLUP_MAX_BUCKETS_PER_JOB="${TRAFFIC_TALKERS_MAX_BUCKETS_PER_JOB:-${TRAFFIC_ROLLUP_MAX_BUCKETS_PER_JOB:-15}}"

exec python3 /app/scripts/traffic_rollup_async.py \
  --jobs traffic_asn_1m,traffic_asn_1h,traffic_asn_pair_1m,traffic_asn_pair_1h
