CREATE TABLE IF NOT EXISTS default.asn_names
(
    `asn` UInt32,
    `name` String,
    `org_id` String DEFAULT '',
    `source` LowCardinality(String) DEFAULT 'manual',
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY asn
SETTINGS index_granularity = 8192;
