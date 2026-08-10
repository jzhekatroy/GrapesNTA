-- Cabinet client aggregates: cheaper bucket maintenance.
--
-- Two problems this fixes on installs that already ran migrate_traffic_client.sql
-- and migrate_traffic_client_vitrines.sql:
--
--   1. The hourly tables were partitioned by month, so the rollup runner's
--      per-bucket "ALTER ... DELETE WHERE hour = X" (used on every re-run and
--      backfill) rewrote a whole month of parts instead of a single day. The
--      operator-side hourly aggregates already partition by day.
--   2. ORDER BY starts with client_id, so the bucket column is not a primary key
--      prefix and both the DELETE predicate and the idempotency probe that runs
--      before every insert had to scan the partition end to end. A minmax index
--      on the bucket column restores granule pruning while keeping the read
--      layout ("one client over a period") intact.
--
-- The hourly tables need a new partition key, which cannot be altered, so they
-- are dropped and recreated: re-run the rollups for the range you want to keep
-- afterwards. The minute/day tables only gain an index.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_traffic_client_layout.sql

DROP TABLE IF EXISTS default.traffic_client_1h SYNC;

CREATE TABLE default.traffic_client_1h
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
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_client_country_1h SYNC;

CREATE TABLE default.traffic_client_country_1h
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

DROP TABLE IF EXISTS default.traffic_client_service_1h SYNC;

CREATE TABLE default.traffic_client_service_1h
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

ALTER TABLE default.traffic_client_1m ADD INDEX IF NOT EXISTS idx_minute minute TYPE minmax GRANULARITY 1;
ALTER TABLE default.traffic_client_1m MATERIALIZE INDEX idx_minute SETTINGS mutations_sync = 1;

ALTER TABLE default.traffic_client_1d ADD INDEX IF NOT EXISTS idx_day day TYPE minmax GRANULARITY 1;
ALTER TABLE default.traffic_client_1d MATERIALIZE INDEX idx_day SETTINGS mutations_sync = 1;

ALTER TABLE default.traffic_client_country_1d ADD INDEX IF NOT EXISTS idx_day day TYPE minmax GRANULARITY 1;
ALTER TABLE default.traffic_client_country_1d MATERIALIZE INDEX idx_day SETTINGS mutations_sync = 1;

ALTER TABLE default.traffic_client_service_1d ADD INDEX IF NOT EXISTS idx_day day TYPE minmax GRANULARITY 1;
ALTER TABLE default.traffic_client_service_1d MATERIALIZE INDEX idx_day SETTINGS mutations_sync = 1;
