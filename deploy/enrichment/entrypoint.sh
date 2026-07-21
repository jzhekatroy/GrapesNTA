#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

mkdir -p /var/lib/geoloaderd/cache /var/log/grapesnta 2>/dev/null || true

# Point loaders at HTTP shim (native clickhouse-client often SIGILL on older CPUs).
export GEOLOADERD_CLICKHOUSE_CLIENT="${GEOLOADERD_CLICKHOUSE_CLIENT:-/usr/local/bin/clickhouse-client}"
export BGPORIGIN_CLICKHOUSE_CLIENT="${BGPORIGIN_CLICKHOUSE_CLIENT:-/usr/local/bin/clickhouse-client}"
export ASNNAMES_CLICKHOUSE_CLIENT="${ASNNAMES_CLICKHOUSE_CLIENT:-/usr/local/bin/clickhouse-client}"
export CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"

# Prefer geoloaderd / bgp credentials for HTTP shim defaults.
export CLICKHOUSE_HTTP_HOST="${GEOLOADERD_CH_HOST:-${BGPORIGIN_CH_HOST:-127.0.0.1}}"
export CLICKHOUSE_HTTP_USER="${GEOLOADERD_CH_USER:-${BGPORIGIN_CH_USER:-default}}"
export CLICKHOUSE_HTTP_PASSWORD="${GEOLOADERD_CH_PASSWORD:-${BGPORIGIN_CH_PASSWORD:-}}"

echo "grapes-enrichment: starting scheduler"
exec python3 /app/scheduler.py
