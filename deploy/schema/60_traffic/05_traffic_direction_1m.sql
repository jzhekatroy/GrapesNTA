CREATE TABLE IF NOT EXISTS default.traffic_direction_1m
(
    `minute` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, direction)
SETTINGS index_granularity = 8192;
