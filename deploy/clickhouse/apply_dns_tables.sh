#!/usr/bin/env bash
# Apply dns_log + dns_answers DDL on ClickHouse.
#
# Usage:
#   ./deploy/clickhouse/apply_dns_tables.sh
#   CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' ./deploy/clickhouse/apply_dns_tables.sh
#
# Requires clickhouse-client on PATH.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

CH_HOST="${CH_HOST:-127.0.0.1}"
CH_PORT="${CH_PORT:-9000}"
CH_USER="${CH_USER:-default}"
CH_PASSWORD="${CH_PASSWORD:-}"
CH_DATABASE="${CH_DATABASE:-default}"
DNS_TABLE_DATABASE="${DNS_TABLE_DATABASE:-default}"

args=(
  --host "$CH_HOST"
  --port "$CH_PORT"
  --user "$CH_USER"
  --database "$CH_DATABASE"
)
if [[ -n "$CH_PASSWORD" ]]; then
  args+=(--password "$CH_PASSWORD")
fi

run_sql() {
  local file="$1"
  echo "==> $(basename "$file")"
  clickhouse-client "${args[@]}" --multiquery <"$file"
}

echo "Applying DNS tables to ${CH_HOST}:${CH_PORT}/${DNS_TABLE_DATABASE}"
run_sql "$ROOT/deploy/clickhouse/dns_log.sql"
run_sql "$ROOT/deploy/clickhouse/dns_answers.sql"

echo "OK"
clickhouse-client "${args[@]}" --query "
SELECT
    name,
    engine,
    formatReadableQuantity(total_rows) AS rows
FROM system.tables
WHERE database = '${DNS_TABLE_DATABASE}'
  AND name IN ('dns_log', 'dns_answers')
ORDER BY name
FORMAT PrettyCompact
"
