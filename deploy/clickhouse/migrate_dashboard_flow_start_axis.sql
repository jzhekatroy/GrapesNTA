-- Migration: switch dashboard traffic rollups from export-time to flow-start
-- time axis to remove the batch-export "sawtooth".
--
-- Safe to run on an existing database: it only recreates the materialized
-- views (the SELECT side), leaving the target tables traffic_dashboard_1m /
-- traffic_dashboard_1h and all historical rows untouched. New minutes/hours
-- will be aggregated by toStartOf*(time_flow_start_ns) going forward.
--
-- Apply:
--   clickhouse-client --host <h> --port <p> --user <u> --password <pw> \
--     --multiquery < deploy/clickhouse/migrate_dashboard_flow_start_axis.sql
--
-- Note: history aggregated before this migration stays bucketed by export time.
-- That older range keeps its previous shape; only data ingested after the
-- migration is smoothed. To re-smooth history, repopulate the target tables
-- from flows_raw with toStartOf*(time_flow_start_ns) over the desired range.

DROP TABLE IF EXISTS default.traffic_dashboard_1m_mv;

CREATE MATERIALIZED VIEW default.traffic_dashboard_1m_mv
TO default.traffic_dashboard_1m
AS
SELECT
    toStartOfMinute(time_flow_start_ns) AS minute,
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
    minute,
    source_id;

DROP TABLE IF EXISTS default.traffic_dashboard_1h_mv;

CREATE MATERIALIZED VIEW default.traffic_dashboard_1h_mv
TO default.traffic_dashboard_1h
AS
SELECT
    toStartOfHour(time_flow_start_ns) AS hour,
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
    hour,
    source_id;
