CREATE TABLE IF NOT EXISTS default.net_l3_prefixes
(
    `prefix` String,
    `family` UInt8,
    `entity_id` LowCardinality(String) DEFAULT '',
    `role` LowCardinality(String) DEFAULT 'remote',
    `display_name` String DEFAULT '',
    `comment` String DEFAULT '',
    `enabled` UInt8,
    `source` LowCardinality(String) DEFAULT 'manual',
    `updated_at` DateTime DEFAULT now(),
    `origin_asn` UInt32 DEFAULT 0
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;
