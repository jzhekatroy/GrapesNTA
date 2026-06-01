-- Flow observation points / data sources registry.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_flow_sources.sql

CREATE TABLE IF NOT EXISTS default.net_flow_sources
(
    source_id          String,
    display_name       String,
    source_type        LowCardinality(String),
    collector_id       String DEFAULT '',
    location           String DEFAULT '',
    description        String DEFAULT '',
    include_in_total   UInt8 DEFAULT 1,
    enabled            UInt8 DEFAULT 1,
    updated_at         DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY source_id
SETTINGS index_granularity = 8192;

DROP VIEW IF EXISTS default.net_flow_sources_enabled;

CREATE VIEW default.net_flow_sources_enabled AS
SELECT
    source_id,
    display_name,
    source_type,
    collector_id,
    location,
    description,
    include_in_total,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        source_id,
        argMax(display_name, updated_at) AS display_name,
        argMax(source_type, updated_at) AS source_type,
        argMax(collector_id, updated_at) AS collector_id,
        argMax(location, updated_at) AS location,
        argMax(description, updated_at) AS description,
        argMax(include_in_total, updated_at) AS include_in_total,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_flow_sources
    GROUP BY source_id
)
WHERE enabled_latest = 1;

-- Seed defaults (safe to re-run; ReplacingMergeTree keeps latest row per source_id).
INSERT INTO default.net_flow_sources
    (source_id, display_name, source_type, collector_id, location, description, include_in_total, enabled)
VALUES
    ('xdp-default', 'Default XDP mirror', 'xdp', '', '', 'Initial xdpflowd source', 1, 1),
    ('dns-default', 'Default DNS mirror', 'dns', '', '', 'Initial dnsflowd source', 0, 1);
