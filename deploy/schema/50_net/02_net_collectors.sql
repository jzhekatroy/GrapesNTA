CREATE TABLE IF NOT EXISTS default.net_collectors
(
    `collector_id` String,
    `location_id` String DEFAULT '',
    `display_name` String,
    `hostname` String DEFAULT '',
    `comment` String DEFAULT '',
    `enabled` UInt8 DEFAULT 1,
    `updated_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY collector_id
SETTINGS index_granularity = 8192;
