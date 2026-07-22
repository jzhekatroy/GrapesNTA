#!/bin/sh
set -eu

if [ -f /app/.env ]; then
  set -a
  # shellcheck disable=SC1091
  . /app/.env
  set +a
fi

# Force HTTP shim (native clickhouse-client often SIGILL on older CPUs).
# Prefer SNMP_SYNC_*; else reuse compose-injected CLICKHOUSE_HTTP_* so we do
# not blank the password or fall back to the script default user "develop".
export SNMP_SYNC_CLICKHOUSE_CLIENT=/usr/local/bin/clickhouse-client
export SNMP_SYNC_CH_HOST="${SNMP_SYNC_CH_HOST:-${CLICKHOUSE_HTTP_HOST:-127.0.0.1}}"
export SNMP_SYNC_CH_USER="${SNMP_SYNC_CH_USER:-${CLICKHOUSE_HTTP_USER:-default}}"
export SNMP_SYNC_CH_PASSWORD="${SNMP_SYNC_CH_PASSWORD:-${CLICKHOUSE_HTTP_PASSWORD:-}}"
export CLICKHOUSE_HTTP_HOST="${SNMP_SYNC_CH_HOST}"
export CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_HTTP_PORT:-8123}"
export CLICKHOUSE_HTTP_USER="${SNMP_SYNC_CH_USER}"
export CLICKHOUSE_HTTP_PASSWORD="${SNMP_SYNC_CH_PASSWORD}"

exec /app/bin/run_job.sh snmp-iface-sync python3 /app/scripts/snmp_iface_sync.py
