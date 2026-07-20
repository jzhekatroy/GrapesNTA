CREATE TABLE IF NOT EXISTS default.net_locations
(
    `location_id` String,
    `display_name` String,
    `city` String DEFAULT '',
    `country` LowCardinality(String) DEFAULT '',
    `comment` String DEFAULT '',
    `enabled` UInt8 DEFAULT 1,
    `updated_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY location_id
SETTINGS index_granularity = 8192;
