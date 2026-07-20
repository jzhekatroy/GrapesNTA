CREATE TABLE IF NOT EXISTS default.traffic_asn_pair_1m
(
    `minute` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `src_asn` UInt32,
    `dst_asn` UInt32,
    `src_as_name` String,
    `dst_as_name` String,
    `src_as_country` LowCardinality(String),
    `dst_as_country` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, direction, src_asn, dst_asn)
TTL minute + toIntervalDay(2)
SETTINGS index_granularity = 8192;
