-- Minute-level traffic by IP protocol number and direction.
--
-- `proto` is the raw IP protocol number from flows_raw. The aggregate keeps
-- every observed protocol instead of limiting rows to TCP/UDP/ICMP.
--
-- Production ingest: NO sync Materialized View. Table is filled by async rollup
-- job traffic_protocol_1m (scripts/traffic_rollup_async.py). SELECT body:
-- scripts/traffic_rollup_jobs.py

CREATE TABLE IF NOT EXISTS default.traffic_protocol_1m
(
    minute      DateTime('UTC'),
    source_id   LowCardinality(String),
    proto       UInt32,
    direction   LowCardinality(String),
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, proto, direction)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_protocol_1m_mv;
