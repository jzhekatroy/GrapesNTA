-- Collectors catalog: a collector belongs to a location and owns flow sources.
--
-- Apply after net_locations.sql:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_collectors.sql
--
-- Relationship:
--   net_collectors.location_id    -> net_locations.location_id
--   net_flow_sources.collector_id -> net_collectors.collector_id

CREATE TABLE IF NOT EXISTS default.net_collectors
(
    collector_id String,
    location_id  String DEFAULT '',
    display_name String,
    hostname     String DEFAULT '',
    comment      String DEFAULT '',
    enabled      UInt8 DEFAULT 1,
    updated_at   DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY collector_id
SETTINGS index_granularity = 8192;

DROP VIEW IF EXISTS default.net_collectors_enabled;

CREATE VIEW default.net_collectors_enabled AS
SELECT
    collector_id,
    location_id,
    display_name,
    hostname,
    comment,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        collector_id,
        argMax(location_id, updated_at) AS location_id,
        argMax(display_name, updated_at) AS display_name,
        argMax(hostname, updated_at) AS hostname,
        argMax(comment, updated_at) AS comment,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_collectors
    GROUP BY collector_id
)
WHERE enabled_latest = 1;
