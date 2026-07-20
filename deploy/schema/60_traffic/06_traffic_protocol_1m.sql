CREATE TABLE IF NOT EXISTS default.traffic_protocol_1m
(
    `minute` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `proto` UInt32,
    `direction` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, proto, direction)
SETTINGS index_granularity = 8192;
