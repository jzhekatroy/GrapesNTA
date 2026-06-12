-- Daily dashboard rollup for long dashboard windows (month+).
--
-- This table stores daily totals by source_id. Use it for total traffic and
-- average speed over long periods. For peak speed, query traffic_dashboard_1h
-- (or traffic_dashboard_1m when exact minute-level peaks are required).
--
-- Production ingest: NO sync Materialized View. Table is filled by async rollup
-- job traffic_dashboard_1d (scripts/traffic_rollup_async.py). SELECT body:
-- scripts/traffic_rollup_jobs.py

CREATE TABLE IF NOT EXISTS default.traffic_dashboard_1d
(
    day              DateTime('UTC'),
    source_id        LowCardinality(String),

    total_bytes      UInt64,
    in_bytes         UInt64,
    out_bytes        UInt64,
    transit_bytes    UInt64,
    internal_bytes   UInt64,
    unknown_bytes    UInt64,

    total_packets    UInt64,
    in_packets       UInt64,
    out_packets      UInt64,
    transit_packets  UInt64,
    internal_packets UInt64,
    unknown_packets  UInt64,

    total_flows      UInt64,
    in_flows         UInt64,
    out_flows        UInt64,
    transit_flows    UInt64,
    internal_flows   UInt64,
    unknown_flows    UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (day, source_id)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_dashboard_1d_mv;
