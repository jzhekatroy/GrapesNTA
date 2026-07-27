CREATE TABLE IF NOT EXISTS default.net_direction_settings
(
    `settings_id` String DEFAULT 'global',
    `direction_mode` LowCardinality(String) DEFAULT 'prefixes',
    `default_boundary` LowCardinality(String) DEFAULT 'unknown',
    `one_sided` LowCardinality(String) DEFAULT 'strict',
    `updated_by` String DEFAULT '',
    `updated_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY settings_id
SETTINGS index_granularity = 8192;
