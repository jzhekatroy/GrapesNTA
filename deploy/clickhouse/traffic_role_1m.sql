-- Minute-level traffic by L3 role and direction.
--
-- Uses src_role for out/internal; dst_role for in when src_role is empty.
--
-- Production ingest: NO sync Materialized View. Table is filled by async rollup
-- job traffic_role_1m (scripts/traffic_rollup_async.py). SELECT body:
-- scripts/traffic_rollup_jobs.py

CREATE TABLE IF NOT EXISTS default.traffic_role_1m
(
    minute      DateTime('UTC'),
    source_id   LowCardinality(String),
    direction   LowCardinality(String),
    role        LowCardinality(String),
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, direction, role)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_role_1m_mv;
