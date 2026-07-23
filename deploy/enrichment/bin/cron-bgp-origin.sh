#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

export BGPORIGIN_CLICKHOUSE_CLIENT=/usr/local/bin/clickhouse-client
export CLICKHOUSE_HTTP_HOST="${BGPORIGIN_CH_HOST:-127.0.0.1}"
export CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
export CLICKHOUSE_HTTP_USER="${BGPORIGIN_CH_USER:-default}"
export CLICKHOUSE_HTTP_PASSWORD="${BGPORIGIN_CH_PASSWORD:-}"

# shellcheck disable=SC1091
. /app/bin/fix_dict_source.sh
fix_dict_source BGPORIGIN

exec /app/bin/run_job.sh bgp-origin python3 /app/scripts/rebuild_bgp_origin_asn.py
