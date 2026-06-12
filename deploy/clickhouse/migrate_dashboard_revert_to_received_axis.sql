-- DEPRECATED: dashboard axis revert no longer recreates sync materialized views.
--
-- Production uses async rollups (scripts/traffic_rollup_async.py). Change the
-- time column in scripts/traffic_rollup_jobs.py for dashboard jobs instead of
-- attaching sync MV on flows_raw ingest.
--
-- To rebuild history, run async backfill for the desired range.
-- See docs/CLICKHOUSE_DB_SETUP_RUNBOOK.md §7.

SELECT 'migrate_dashboard_revert_to_received_axis.sql is deprecated; use async rollups' AS notice;
