CREATE TABLE IF NOT EXISTS default.traffic_client_1d
(
    `day` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64,
    INDEX idx_day day TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (client_id, day, source_id, direction)
TTL day + toIntervalDay(730)
SETTINGS index_granularity = 8192;
