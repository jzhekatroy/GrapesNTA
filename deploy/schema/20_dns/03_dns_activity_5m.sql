CREATE TABLE IF NOT EXISTS default.dns_activity_5m
(
    `bucket` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `qtype` LowCardinality(String),
    `rcode` UInt8,
    `queries` UInt64,
    `responses` UInt64,
    `nxdomain` UInt64,
    `servfail` UInt64,
    `raw_bytes` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, source_id, qtype, rcode)
TTL bucket + toIntervalDay(90)
SETTINGS index_granularity = 8192;
