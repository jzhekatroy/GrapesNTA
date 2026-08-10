-- Cabinet client aggregates (base layer: client + in/out).
-- Safe to re-run.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_traffic_client.sql

CREATE TABLE IF NOT EXISTS default.traffic_client_1m
(
    `minute` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (client_id, minute, source_id, direction)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.traffic_client_1h
(
    `hour` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (client_id, hour, source_id, direction)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.traffic_client_1d
(
    `day` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (client_id, day, source_id, direction)
SETTINGS index_granularity = 8192;
