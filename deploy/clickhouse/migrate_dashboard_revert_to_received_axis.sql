-- Revert: restore dashboard traffic rollups to the time_received_ns axis.
--
-- The flow-start axis (migrate_dashboard_flow_start_axis.sql) did not smooth the
-- graph: under batch full-drain, elephant flows are re-created with a fresh
-- first_seen at every drain tick, so their bytes still clump, and bucketing by
-- flow start sags the live edge (recent flows not yet exported). We revert to
-- the export-time axis here; the proper smoothing is a rate-spread rollup over
-- [time_flow_start_ns, time_flow_end_ns] (built separately).
--
-- Safe on an existing database: recreates only the materialized views; target
-- tables and history are untouched.
--
-- Apply:
--   clickhouse-client --host <h> --port <p> --user <u> --password <pw> \
--     --multiquery < deploy/clickhouse/migrate_dashboard_revert_to_received_axis.sql

DROP TABLE IF EXISTS default.traffic_dashboard_1m_mv;

CREATE MATERIALIZED VIEW default.traffic_dashboard_1m_mv
TO default.traffic_dashboard_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,
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
    toStartOfHour(time_received_ns) AS hour,
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
