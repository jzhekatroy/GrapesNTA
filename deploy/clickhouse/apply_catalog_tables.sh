#!/usr/bin/env bash
# Apply the network catalog DDL on ClickHouse (locations + collectors).
#
# Idempotent: every file uses CREATE TABLE IF NOT EXISTS / CREATE VIEW, so the
# script is safe to re-run. UI/backend never creates these tables by hand —
# this script is the single source of truth for the catalog schema.
#
# Usage:
#   ./deploy/clickhouse/apply_catalog_tables.sh
#   CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' \
#     ./deploy/clickhouse/apply_catalog_tables.sh
#
# Requires clickhouse-client on PATH.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

CH_HOST="${CH_HOST:-127.0.0.1}"
CH_PORT="${CH_PORT:-9000}"
CH_USER="${CH_USER:-default}"
CH_PASSWORD="${CH_PASSWORD:-}"
CH_DATABASE="${CH_DATABASE:-default}"

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

echo "Applying network catalog tables to ${CH_HOST}:${CH_PORT}/${CH_DATABASE}"

# Order matters: locations first (collectors reference location_id).
run_sql "$ROOT/deploy/clickhouse/net_locations.sql"
run_sql "$ROOT/deploy/clickhouse/net_collectors.sql"

echo "OK"
clickhouse-client "${args[@]}" --query "
SELECT
    name,
    engine
FROM system.tables
WHERE database = '${CH_DATABASE}'
  AND name IN (
    'net_locations', 'net_locations_enabled',
    'net_collectors', 'net_collectors_enabled')
ORDER BY name
FORMAT PrettyCompact
"
