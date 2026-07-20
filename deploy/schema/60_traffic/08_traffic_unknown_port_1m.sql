CREATE TABLE IF NOT EXISTS default.traffic_unknown_port_1m
(
    `minute` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `proto` UInt32,
    `transport` LowCardinality(String),
    `port_side` LowCardinality(String),
    `port` UInt16,
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, direction, transport, port, port_side, proto)
SETTINGS index_granularity = 8192;
