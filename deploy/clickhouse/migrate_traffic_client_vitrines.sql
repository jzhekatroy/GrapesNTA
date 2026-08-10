-- Cabinet client showcase aggregates: country / service (hour + day).
-- Safe to re-run.
--
-- There is deliberately no ASN vitrine: remote ASN tops cost an extra pass over
-- flows_raw plus a registry join, and the cabinet needs countries far more. ASN
-- detail stays available through raw-flow analysis over a short window.
--
-- ORDER BY starts with client_id because every cabinet query is scoped to one
-- client, which leaves the bucket column outside the primary key prefix: the
-- idx_hour / idx_day minmax indexes are what keeps the rollup runner's
-- idempotency probe and per-bucket DELETE from scanning the whole partition.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_traffic_client_vitrines.sql

CREATE TABLE IF NOT EXISTS default.traffic_client_country_1h
(
    `hour` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `country_code` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64,
    INDEX idx_hour hour TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(hour)
ORDER BY (client_id, hour, source_id, direction, country_code)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.traffic_client_country_1d
(
    `day` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `country_code` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64,
    INDEX idx_day day TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (client_id, day, source_id, direction, country_code)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.traffic_client_service_1h
(
    `hour` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `transport` LowCardinality(String),
    `service_code` LowCardinality(String),
    `service_name` String,
    `category` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64,
    INDEX idx_hour hour TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(hour)
ORDER BY (client_id, hour, source_id, direction, transport, category, service_code, service_name)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.traffic_client_service_1d
(
    `day` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `transport` LowCardinality(String),
    `service_code` LowCardinality(String),
    `service_name` String,
    `category` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64,
    INDEX idx_day day TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (client_id, day, source_id, direction, transport, category, service_code, service_name)
SETTINGS index_granularity = 8192;
