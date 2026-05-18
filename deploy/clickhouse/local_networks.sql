-- Local network prefixes and ASNs used to classify traffic direction.
--
-- Apply once, then populate default.local_networks either manually (MoonShine)
-- or via scripts/load_local_networks_from_asn.py.
-- default.local_asns stores the ASNs that should be treated as local/customer.
-- xdpflowd now reads local_networks_enabled + local_asns_enabled + vlan_map_enabled
-- into memory and writes ready-to-aggregate direction fields into flows_raw.
--
-- This deployment runs without default.local_networks_dict because the remote
-- ClickHouse 24.11 instance rejects dictionary DDL through the SQL proxy. The
-- XML template is kept in deploy/clickhouse/local_networks_dict.xml for future
-- use, but dashboards should read collector-built aggregates instead of
-- classifying raw traffic in SQL.

CREATE TABLE IF NOT EXISTS default.local_networks
(
    prefix      String,
    family      UInt8,
    operator_id LowCardinality(String) DEFAULT '',
    kind        LowCardinality(String) DEFAULT 'customer',
    name        String,
    source      LowCardinality(String),
    enabled     UInt8,
    updated_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;

ALTER TABLE default.local_networks
ADD COLUMN IF NOT EXISTS operator_id LowCardinality(String) DEFAULT '' AFTER family,
ADD COLUMN IF NOT EXISTS kind LowCardinality(String) DEFAULT 'customer' AFTER operator_id;

CREATE TABLE IF NOT EXISTS default.local_asns
(
    asn         UInt32,
    operator_id LowCardinality(String) DEFAULT '',
    name        String,
    source      LowCardinality(String),
    enabled     UInt8,
    updated_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY asn
SETTINGS index_granularity = 8192;

ALTER TABLE default.local_asns
ADD COLUMN IF NOT EXISTS operator_id LowCardinality(String) DEFAULT '' AFTER asn;

-- Keep the dictionary source free from FINAL. ReplacingMergeTree deduplication is
-- resolved here by argMax over updated_at, so disabled rows immediately remove a
-- prefix from the effective dictionary after SYSTEM RELOAD DICTIONARY.
-- ClickHouse 24.11 does not support CREATE OR REPLACE VIEW, so use an explicit
-- DROP + CREATE sequence for idempotent deploys.
DROP TABLE IF EXISTS default.local_networks_enabled;

CREATE VIEW default.local_networks_enabled AS
SELECT
    family,
    prefix,
    operator_id,
    kind,
    name,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        family,
        prefix,
        argMax(operator_id, updated_at) AS operator_id,
        argMax(kind, updated_at) AS kind,
        argMax(name, updated_at) AS name,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.local_networks
    GROUP BY
        family,
        prefix
)
WHERE enabled_latest = 1;

DROP TABLE IF EXISTS default.local_asns_enabled;

CREATE VIEW default.local_asns_enabled AS
SELECT
    asn,
    operator_id,
    name,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        asn,
        argMax(operator_id, updated_at) AS operator_id,
        argMax(name, updated_at) AS name,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.local_asns
    GROUP BY asn
)
WHERE enabled_latest = 1;
