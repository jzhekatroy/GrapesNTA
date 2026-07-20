CREATE TABLE IF NOT EXISTS default.net_flow_sources
(
    `source_id` String,
    `display_name` String,
    `source_type` LowCardinality(String),
    `collector_id` String DEFAULT '',
    `location` String DEFAULT '',
    `description` String DEFAULT '',
    `include_in_total` UInt8 DEFAULT 1,
    `enabled` UInt8 DEFAULT 1,
    `updated_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY source_id
SETTINGS index_granularity = 8192;
