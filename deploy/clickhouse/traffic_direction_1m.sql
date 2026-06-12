-- Minute-level traffic by precomputed direction.
--
-- Source columns are written by xdpflowd classifier:
--   direction = in | out | internal | transit | unknown
--
-- Production ingest: NO sync Materialized View. Table is filled by async rollup
-- job traffic_direction_1m (scripts/traffic_rollup_async.py). SELECT body:
-- scripts/traffic_rollup_jobs.py

CREATE TABLE IF NOT EXISTS default.traffic_direction_1m
(
    minute      DateTime('UTC'),
    source_id   LowCardinality(String),
    direction   LowCardinality(String),
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, direction)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_direction_1m_mv;
