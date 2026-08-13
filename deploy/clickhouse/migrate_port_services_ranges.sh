#!/usr/bin/env bash
# Migrate default.port_services from the old single-port schema:
#   transport, port, service_code, ...
# to the range-aware schema:
#   transport, port_from, port_to, service_code, ...
#
# The old table is preserved as default.port_services_backup_<timestamp>.
#
# Usage:
#   CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='...' \
#     ./deploy/clickhouse/migrate_port_services_ranges.sh

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

query() {
  clickhouse-client "${args[@]}" --query "$1"
}

multiquery() {
  clickhouse-client "${args[@]}" --multiquery
}

table_exists="$(query "
SELECT count()
FROM system.tables
WHERE database = '${CH_DATABASE}'
  AND name = 'port_services'
")"

if [[ "$table_exists" == "0" ]]; then
  echo "port_services does not exist; applying fresh DDL"
  clickhouse-client "${args[@]}" --multiquery <"$ROOT/deploy/schema/50_net/08_port_services.sql"
  exit 0
fi

has_port_from="$(query "
SELECT count()
FROM system.columns
WHERE database = '${CH_DATABASE}'
  AND table = 'port_services'
  AND name = 'port_from'
")"

if [[ "$has_port_from" != "0" ]]; then
  echo "port_services already has port_from/port_to; recreating views only"
  multiquery <<'SQL'
DROP VIEW IF EXISTS default.port_services_expanded_enabled;
DROP VIEW IF EXISTS default.port_services_enabled;

CREATE VIEW default.port_services_enabled AS
SELECT
    transport,
    port_from,
    port_to,
    if(port_from = port_to, toString(port_from), concat(toString(port_from), '-', toString(port_to))) AS port_label,
    if(port_from = port_to, port_from, toUInt16(0)) AS port,
    service_code,
    service_name,
    category,
    description,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        transport,
        port_from,
        port_to,
        argMax(service_code, updated_at) AS service_code,
        argMax(service_name, updated_at) AS service_name,
        argMax(category, updated_at) AS category,
        argMax(description, updated_at) AS description,
        argMax(is_enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.port_services
    GROUP BY
        transport,
        port_from,
        port_to
)
WHERE enabled_latest = 1
  AND port_from <= port_to;

CREATE VIEW default.port_services_expanded_enabled AS
SELECT
    transport,
    toUInt16(arrayJoin(range(toUInt32(port_from), toUInt32(port_to) + 1))) AS port,
    port_from,
    port_to,
    port_label,
    service_code,
    service_name,
    category,
    description,
    updated_at
FROM default.port_services_enabled;
SQL
  echo "OK"
  exit 0
fi

has_port="$(query "
SELECT count()
FROM system.columns
WHERE database = '${CH_DATABASE}'
  AND table = 'port_services'
  AND name = 'port'
")"

if [[ "$has_port" == "0" ]]; then
  echo "ERROR: port_services has neither port nor port_from columns; manual inspection required" >&2
  exit 1
fi

backup="port_services_backup_$(date +%Y%m%d_%H%M%S)"

echo "Migrating ${CH_DATABASE}.port_services to range-aware schema"
echo "Backup table will be ${CH_DATABASE}.${backup}"

multiquery <<SQL
DROP VIEW IF EXISTS default.port_services_expanded_enabled;
DROP VIEW IF EXISTS default.port_services_enabled;
DROP TABLE IF EXISTS default.port_services_v2;

CREATE TABLE default.port_services_v2
(
    transport     LowCardinality(String),
    port_from     UInt16,
    port_to       UInt16,
    service_code  LowCardinality(String),
    service_name  String,
    category      LowCardinality(String),
    description   String DEFAULT '',
    is_enabled    UInt8 DEFAULT 1,
    updated_at    DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (transport, port_from, port_to)
SETTINGS index_granularity = 8192;

INSERT INTO default.port_services_v2
    (transport, port_from, port_to, service_code, service_name, category, description, is_enabled, updated_at)
SELECT
    transport,
    port AS port_from,
    port AS port_to,
    service_code,
    service_name,
    category,
    description,
    is_enabled,
    updated_at
FROM default.port_services FINAL;

RENAME TABLE default.port_services TO default.${backup}, default.port_services_v2 TO default.port_services;

CREATE VIEW default.port_services_enabled AS
SELECT
    transport,
    port_from,
    port_to,
    if(port_from = port_to, toString(port_from), concat(toString(port_from), '-', toString(port_to))) AS port_label,
    if(port_from = port_to, port_from, toUInt16(0)) AS port,
    service_code,
    service_name,
    category,
    description,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        transport,
        port_from,
        port_to,
        argMax(service_code, updated_at) AS service_code,
        argMax(service_name, updated_at) AS service_name,
        argMax(category, updated_at) AS category,
        argMax(description, updated_at) AS description,
        argMax(is_enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.port_services
    GROUP BY
        transport,
        port_from,
        port_to
)
WHERE enabled_latest = 1
  AND port_from <= port_to;

CREATE VIEW default.port_services_expanded_enabled AS
SELECT
    transport,
    toUInt16(arrayJoin(range(toUInt32(port_from), toUInt32(port_to) + 1))) AS port,
    port_from,
    port_to,
    port_label,
    service_code,
    service_name,
    category,
    description,
    updated_at
FROM default.port_services_enabled;
SQL

echo "OK"
query "
SELECT
    'active_rules' AS metric,
    count() AS value
FROM default.port_services_enabled
UNION ALL
SELECT
    'expanded_ports' AS metric,
    count() AS value
FROM default.port_services_expanded_enabled
FORMAT PrettyCompact
"
