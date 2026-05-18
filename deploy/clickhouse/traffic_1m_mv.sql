-- Minute-level total traffic aggregate materialized view.
--
-- Direction is precomputed by xdpflowd and stored in default.flows_raw. This MV
-- must stay lightweight: no dictGet, no joins, no raw prefix checks.
--
-- Apply after:
--   1. default.flows_raw exists;
--   2. deploy/clickhouse/traffic_1m_table.sql was applied;
--   3. deploy/clickhouse/flows_raw_extensions.sql was applied.
--
-- Compatible with old clickhouse-client (18.x) without --multiquery: pipe
-- the file or pass it via --query "$(cat ...)". Drop the existing MV first
-- with DROP TABLE IF EXISTS default.traffic_1m_mv.

CREATE MATERIALIZED VIEW IF NOT EXISTS default.traffic_1m_mv
TO default.traffic_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM default.flows_raw
GROUP BY
    minute,
    direction
