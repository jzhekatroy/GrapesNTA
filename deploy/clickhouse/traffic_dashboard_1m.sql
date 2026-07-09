-- Pivot minute aggregate for dashboard traffic charts (bps / pps / flows/s).
--
-- One row per minute per source_id with pre-split direction columns.
--
-- Time axis: buckets by time_received_ns (collector export / ClickHouse receive
-- time), same as the other minute traffic_* rollups. This makes UI volume/bps
-- match bytes actually delivered in that minute and keeps charts independent of
-- XDP_NF_ACTIVE. Bucketing by time_flow_start_ns previously pushed long active
-- flows outside the selected UI window (~2-3% at NF_ACTIVE=120s).
--
-- LIVE-EDGE CAVEAT: the newest minute is incomplete until the collector flush
-- and rollup safety lag pass. UI queries should exclude the not-yet-complete
-- tail (anchor the window at now() - safety lag); see
-- docs/UI_CLICKHOUSE_QUERIES.md "Time axis and live-edge guard".
--
-- Production ingest: NO sync Materialized Views. Tables are filled by async
-- rollups traffic_dashboard_1m / traffic_dashboard_1h (scripts/traffic_rollup_async.py).
-- SELECT bodies: scripts/traffic_rollup_jobs.py

CREATE TABLE IF NOT EXISTS default.traffic_dashboard_1m
(
    minute           DateTime('UTC'),
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
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_dashboard_1m_mv;

-- Hourly rollup for long dashboard windows.

CREATE TABLE IF NOT EXISTS default.traffic_dashboard_1h
(
    hour             DateTime('UTC'),
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
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, source_id)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_dashboard_1h_mv;
