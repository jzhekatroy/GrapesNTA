-- Minute-level traffic by entity and direction.
--
-- Uses src_entity for out/internal; dst_entity for in when src_entity is empty.
--
-- Production ingest: NO sync Materialized View. Table is filled by async rollup
-- job traffic_entity_1m (scripts/traffic_rollup_async.py). SELECT body:
-- scripts/traffic_rollup_jobs.py

CREATE TABLE IF NOT EXISTS default.traffic_entity_1m
(
    minute      DateTime('UTC'),
    source_id   LowCardinality(String),
    direction   LowCardinality(String),
    entity_id   LowCardinality(String),
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, direction, entity_id)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_entity_1m_mv;
