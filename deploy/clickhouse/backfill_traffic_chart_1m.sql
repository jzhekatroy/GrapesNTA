-- Backfill default.traffic_chart_1m from existing traffic_direction_1m rows.
--
-- Run once after applying traffic_chart_1m.sql. Safe to re-run: SummingMergeTree
-- merges duplicate minute keys on read/optimize.
--
-- Example:
--   clickhouse-client --host 95.215.1.30 --port 6124 --user develop \
--     --password "$CH_PASS" --database default \
--     --queries-file deploy/clickhouse/backfill_traffic_chart_1m.sql
--
-- Optional: limit the window by editing the WHERE clause on minute.

INSERT INTO default.traffic_chart_1m
SELECT
    minute,

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

    sum(flows_count) AS total_flows,
    sumIf(flows_count, direction = 'in') AS in_flows,
    sumIf(flows_count, direction = 'out') AS out_flows,
    sumIf(flows_count, direction = 'transit') AS transit_flows,
    sumIf(flows_count, direction = 'internal') AS internal_flows,
    sumIf(flows_count, direction = 'unknown') AS unknown_flows
FROM default.traffic_direction_1m
WHERE minute >= toDateTime('2026-05-18 00:00:00', 'UTC')
GROUP BY minute
SETTINGS max_threads = 4;
