-- Network entities: stable ids for customers, uplinks, IX peers, internal groups.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_entities.sql

CREATE TABLE IF NOT EXISTS default.net_entities
(
    entity_id    LowCardinality(String),
    display_name String,
    comment      String DEFAULT '',
    enabled      UInt8,
    source       LowCardinality(String) DEFAULT 'manual',
    updated_at   DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY entity_id
SETTINGS index_granularity = 8192;

DROP VIEW IF EXISTS default.net_entities_enabled;

CREATE VIEW default.net_entities_enabled AS
SELECT
    entity_id,
    display_name,
    comment,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        entity_id,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_entities
    GROUP BY entity_id
)
WHERE enabled_latest = 1;
