-- Pivot minute aggregate for dashboard traffic charts (bps / pps / flows/s).
--
-- One row per minute with pre-split direction columns. Faster than reading
-- traffic_direction_1m and running sumIf(direction = ...) on every API request.
--
-- Apply after default.flows_raw and flows_raw_extensions exist.
-- Backfill history from traffic_direction_1m:
--   deploy/clickhouse/backfill_traffic_chart_1m.sql

CREATE TABLE IF NOT EXISTS default.traffic_chart_1m
(
    minute           DateTime('UTC'),

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
ORDER BY minute
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS default.traffic_chart_1m_mv
TO default.traffic_chart_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,

    sum(bytes) AS total_bytes,
    sumIf(bytes, direction = 'in') AS in_bytes,
    sumIf(bytes, direction = 'out') AS out_bytes,
    sumIf(bytes, direction = 'transit') AS transit_bytes,
    sumIf(bytes, direction = 'internal') AS internal_bytes,
    sumIf(bytes, direction = 'unknown') AS unknown_bytes,

    sum(packets) AS total_packets,
    sumIf(packets, direction = 'in') AS in_packets,
    sumIf(packets, direction = 'out') AS out_packets,
    sumIf(packets, direction = 'transit') AS transit_packets,
    sumIf(packets, direction = 'internal') AS internal_packets,
    sumIf(packets, direction = 'unknown') AS unknown_packets,

    count() AS total_flows,
    countIf(direction = 'in') AS in_flows,
    countIf(direction = 'out') AS out_flows,
    countIf(direction = 'transit') AS transit_flows,
    countIf(direction = 'internal') AS internal_flows,
    countIf(direction = 'unknown') AS unknown_flows
FROM default.flows_raw
GROUP BY minute;
