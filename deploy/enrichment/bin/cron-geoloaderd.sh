#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

export GEOLOADERD_CLICKHOUSE_CLIENT="${GEOLOADERD_CLICKHOUSE_CLIENT:-clickhouse-client}"
export GEOLOADERD_CACHE_DIR="${GEOLOADERD_CACHE_DIR:-/var/lib/geoloaderd/cache}"

exec python3 /app/scripts/load_rir_geo.py
