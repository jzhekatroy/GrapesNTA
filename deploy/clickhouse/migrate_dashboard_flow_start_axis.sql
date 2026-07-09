-- DEPRECATED: dashboard axis migration no longer recreates sync materialized views.
--
-- Production uses async rollups (scripts/traffic_rollup_async.py).
-- traffic_dashboard_1m now buckets by time_received_ns (not time_flow_start_ns)
-- so UI volume/bps matches collector delivery and does not depend on
-- XDP_NF_ACTIVE. See scripts/traffic_rollup_jobs.py.
--
-- To rebuild recent history after the axis change, skip/reset
-- traffic_rollup_state for traffic_dashboard_1m (and optionally 1h/1d) and let
-- the timer refill, or run async backfill with --delete-before-insert.
-- See docs/CLICKHOUSE_DB_SETUP_RUNBOOK.md §7.

SELECT 'migrate_dashboard_flow_start_axis.sql is deprecated; dashboard uses time_received_ns via async rollups' AS notice;
