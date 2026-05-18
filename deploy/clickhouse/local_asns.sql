-- Editable ASNs treated as local/customer by xdpflowd.
--
-- This file is safe to apply together with local_networks.sql. It exists as a
-- standalone DDL for operators who manage ASNs separately from prefixes.

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
