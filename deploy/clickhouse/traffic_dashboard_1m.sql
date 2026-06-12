-- Pivot minute aggregate for dashboard traffic charts (bps / pps / flows/s).
--
-- One row per minute per source_id with pre-split direction columns.
--
-- Time axis: buckets by time_flow_start_ns (the flow's real first_seen), NOT
-- time_received_ns (the collector export time). xdpflowd exports flows in
-- batches (batch full-drain every drain interval), so many flows share one
-- export timestamp — bucketing by export time produces a "sawtooth" graph (a
-- spike each drain tick). Per-second measurement on flows_raw confirms that, by
-- flow start, real traffic is smooth (~steady GiB/s), so this axis reflects when
-- traffic actually happened. Ops/freshness keeps using time_received_ns.
--
-- LIVE-EDGE CAVEAT: a flow bucketed at its first_seen reaches ClickHouse only
-- after it is exported (~drain interval + spool, ≈10-15s). So the most recent
-- ~1 bucket is incomplete until that lag passes. UI queries MUST exclude the
-- not-yet-complete tail (anchor the window at now() - 30s); see
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
