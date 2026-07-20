CREATE TABLE IF NOT EXISTS default.net_entities
(
    `entity_id` LowCardinality(String),
    `display_name` String,
    `comment` String DEFAULT '',
    `enabled` UInt8,
    `source` LowCardinality(String) DEFAULT 'manual',
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY entity_id
SETTINGS index_granularity = 8192;
