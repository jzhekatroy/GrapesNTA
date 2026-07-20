CREATE TABLE IF NOT EXISTS default.traffic_entity_1m
(
    `minute` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `entity_id` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, direction, entity_id)
SETTINGS index_granularity = 8192;
