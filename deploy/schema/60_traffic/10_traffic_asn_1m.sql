CREATE TABLE IF NOT EXISTS default.traffic_asn_1m
(
    `minute` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `endpoint_side` LowCardinality(String),
    `direction` LowCardinality(String),
    `endpoint_asn` UInt32,
    `endpoint_as_name` String,
    `endpoint_as_country` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, endpoint_side, direction, endpoint_asn)
TTL minute + toIntervalDay(2)
SETTINGS index_granularity = 8192;
