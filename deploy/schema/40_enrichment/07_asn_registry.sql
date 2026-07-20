CREATE TABLE IF NOT EXISTS default.asn_registry
(
    `asn` UInt32,
    `cc` FixedString(2),
    `rir` LowCardinality(String),
    `status` LowCardinality(String),
    `alloc_date` Date,
    `source` LowCardinality(String),
    `snapshot_ts` DateTime
)
ENGINE = MergeTree
ORDER BY asn
SETTINGS index_granularity = 8192;
