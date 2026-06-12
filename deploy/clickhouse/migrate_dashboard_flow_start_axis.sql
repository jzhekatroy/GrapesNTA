-- DEPRECATED: dashboard axis migration no longer recreates sync materialized views.
--
-- Production uses async rollups (scripts/traffic_rollup_async.py). Dashboard jobs
-- traffic_dashboard_1m / traffic_dashboard_1h already bucket by
-- time_flow_start_ns in scripts/traffic_rollup_jobs.py.
--
-- To rebuild history after this axis change, run async backfill for the desired
-- range with --delete-before-insert and/or higher --max-buckets-per-job.
-- See docs/CLICKHOUSE_DB_SETUP_RUNBOOK.md §7.

SELECT 'migrate_dashboard_flow_start_axis.sql is deprecated; use async rollups' AS notice;
