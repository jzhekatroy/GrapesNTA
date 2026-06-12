-- Minute-level TOP-port helper for the "Other" service slice.
--
-- Rows are emitted only when neither dst nor src port matches port_services.
-- This makes UI drill-down "Other -> TOP 20 ports" cheap without scanning
-- flows_raw.
--
-- Production ingest: NO sync Materialized View. Table is filled by async rollup
-- job traffic_unknown_port_1m (scripts/traffic_rollup_async.py). SELECT body:
-- scripts/traffic_rollup_jobs.py

DROP TABLE IF EXISTS default.traffic_unknown_port_1m_mv;

CREATE TABLE IF NOT EXISTS default.traffic_unknown_port_1m
(
    minute      DateTime('UTC'),
    source_id   LowCardinality(String),
    direction   LowCardinality(String),
    proto       UInt32,
    transport   LowCardinality(String),
    port_side   LowCardinality(String), -- dst / src / unknown
    port        UInt16,
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, direction, transport, port, port_side, proto)
SETTINGS index_granularity = 8192;
