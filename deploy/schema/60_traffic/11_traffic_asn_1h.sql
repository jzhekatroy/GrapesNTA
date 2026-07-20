CREATE TABLE IF NOT EXISTS default.traffic_asn_1h
(
    `hour` DateTime('UTC'),
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
PARTITION BY toYYYYMMDD(hour)
ORDER BY (hour, source_id, endpoint_side, direction, endpoint_asn)
TTL hour + toIntervalDay(90)
SETTINGS index_granularity = 8192;
