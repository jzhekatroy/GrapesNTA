CREATE TABLE IF NOT EXISTS default.ip_asn_prefixes_current
(
    `prefix` String,
    `family` UInt8,
    `origin_asn` UInt32,
    `cc` LowCardinality(String),
    `as_name` String,
    `source` LowCardinality(String),
    `snapshot_ts` DateTime('UTC')
)
ENGINE = MergeTree
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;
