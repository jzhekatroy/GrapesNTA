#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

export GEOLOADERD_CLICKHOUSE_CLIENT=/usr/local/bin/clickhouse-client
export GEOLOADERD_CACHE_DIR="${GEOLOADERD_CACHE_DIR:-/var/lib/geoloaderd/cache}"
export CLICKHOUSE_HTTP_HOST="${GEOLOADERD_CH_HOST:-127.0.0.1}"
export CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
export CLICKHOUSE_HTTP_USER="${GEOLOADERD_CH_USER:-default}"
export CLICKHOUSE_HTTP_PASSWORD="${GEOLOADERD_CH_PASSWORD:-}"

exec python3 /app/scripts/load_rir_geo.py
