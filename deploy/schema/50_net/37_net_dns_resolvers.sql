CREATE TABLE IF NOT EXISTS default.net_dns_resolvers
(
    `resolver_id` String,
    `prefix` String,
    `family` UInt8 DEFAULT 0,
    `role` LowCardinality(String) DEFAULT 'resolver',
    `display_name` String DEFAULT '',
    `comment` String DEFAULT '',
    `enabled` UInt8,
    `source` LowCardinality(String) DEFAULT 'manual',
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY resolver_id
SETTINGS index_granularity = 8192;
