CREATE TABLE IF NOT EXISTS default.geo_prefix_country_staging
(
    `prefix` String,
    `family` UInt8,
    `cc` FixedString(2),
    `rir` LowCardinality(String),
    `status` LowCardinality(String),
    `alloc_date` Date,
    `source` LowCardinality(String),
    `snapshot_ts` DateTime
)
ENGINE = MergeTree
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;
