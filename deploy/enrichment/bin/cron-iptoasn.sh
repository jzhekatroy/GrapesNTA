#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

export IPTOASN_CLICKHOUSE_CLIENT=/usr/local/bin/clickhouse-client
# Reuse the geoloaderd volume so the 40 MB download survives image rebuilds.
export IPTOASN_CACHE_DIR="${IPTOASN_CACHE_DIR:-/var/lib/geoloaderd/cache/iptoasn}"
export CLICKHOUSE_HTTP_HOST="${GEOLOADERD_CH_HOST:-${IPTOASN_CH_HOST:-127.0.0.1}}"
export CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
export CLICKHOUSE_HTTP_USER="${GEOLOADERD_CH_USER:-${IPTOASN_CH_USER:-default}}"
export CLICKHOUSE_HTTP_PASSWORD="${GEOLOADERD_CH_PASSWORD:-${IPTOASN_CH_PASSWORD:-}}"

exec /app/bin/run_job.sh iptoasn python3 /app/scripts/load_iptoasn_prefixes.py
