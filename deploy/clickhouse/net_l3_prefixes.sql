-- L3 prefix classification: provider_public | internal | customer_allocated | customer_transit.
--
-- Apply after net_entities.sql:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_l3_prefixes.sql

CREATE TABLE IF NOT EXISTS default.net_l3_prefixes
(
    prefix       String,
    family       UInt8,
    entity_id    LowCardinality(String) DEFAULT '',
    role         LowCardinality(String) DEFAULT 'remote',
    display_name String DEFAULT '',
    comment      String DEFAULT '',
    enabled      UInt8,
    source       LowCardinality(String) DEFAULT 'manual',
    updated_at   DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;

DROP VIEW IF EXISTS default.net_l3_prefixes_enabled;

CREATE VIEW default.net_l3_prefixes_enabled AS
SELECT
    prefix,
    family,
    entity_id,
    role,
    display_name,
    comment,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        prefix,
        family,
        argMax(entity_id, updated_at) AS entity_id,
        argMax(role, updated_at) AS role,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_l3_prefixes
    GROUP BY
        family,
        prefix
)
WHERE enabled_latest = 1;
