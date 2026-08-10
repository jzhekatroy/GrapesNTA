-- Cabinet client aggregates (base layer: client + in/out).
-- Safe to re-run.
--
-- ORDER BY starts with client_id because every cabinet query is scoped to one
-- client, which leaves the bucket column outside the primary key prefix: the
-- idx_minute / idx_hour / idx_day minmax indexes are what keeps the rollup
-- runner's idempotency probe and per-bucket DELETE from scanning the whole
-- partition.
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
    `flows_count` UInt64,
    INDEX idx_minute minute TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (client_id, minute, source_id, direction)
TTL minute + toIntervalDay(14)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.traffic_client_1h
(
    `hour` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64,
    INDEX idx_hour hour TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(hour)
ORDER BY (client_id, hour, source_id, direction)
TTL hour + toIntervalDay(180)
SETTINGS index_granularity = 8192;

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
