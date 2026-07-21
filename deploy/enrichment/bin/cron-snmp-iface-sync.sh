#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

# Force HTTP shim (native clickhouse-client often SIGILL on older CPUs). The
# script passes --host/--port/--user/--password; the shim rewrites 9000/6124.
export SNMP_SYNC_CLICKHOUSE_CLIENT=/usr/local/bin/clickhouse-client
export CLICKHOUSE_HTTP_HOST="${SNMP_SYNC_CH_HOST:-127.0.0.1}"
export CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
export CLICKHOUSE_HTTP_USER="${SNMP_SYNC_CH_USER:-default}"
export CLICKHOUSE_HTTP_PASSWORD="${SNMP_SYNC_CH_PASSWORD:-}"

exec /app/bin/run_job.sh snmp-iface-sync python3 /app/scripts/snmp_iface_sync.py
