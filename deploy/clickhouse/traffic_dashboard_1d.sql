-- Daily dashboard rollup for long dashboard windows (month+).
--
-- This table stores daily totals by source_id. Use it for total traffic and
-- average speed over long periods. For peak speed, query traffic_dashboard_1h
-- (or traffic_dashboard_1m when exact minute-level peaks are required).

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

CREATE MATERIALIZED VIEW default.traffic_dashboard_1d_mv
TO default.traffic_dashboard_1d
AS
SELECT
    toStartOfDay(time_received_ns) AS day,
    source_id,

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
GROUP BY
    day,
    source_id;
