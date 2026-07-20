CREATE TABLE IF NOT EXISTS default.net_special_ip_prefixes
(
    `prefix` String,
    `family` UInt8,
    `kind` LowCardinality(String),
    `asn_expected` UInt8,
    `country_expected` UInt8,
    `publicly_routable` UInt8,
    `display_name` String DEFAULT '',
    `comment` String DEFAULT '',
    `enabled` UInt8,
    `source` LowCardinality(String) DEFAULT 'system',
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;
