-- DEPRECATED: service rollup MV migration (range-aware port_services join).
--
-- Production uses async rollups (scripts/traffic_rollup_async.py). Range-aware
-- joins live in scripts/traffic_rollup_jobs.py for traffic_service_1m and
-- traffic_unknown_port_1m.
--
-- Run migrate_port_services_ranges.sh first to update port_services schema.
-- To rebuild service aggregates for a period, use async backfill with
-- --delete-before-insert. See docs/CLICKHOUSE_DB_SETUP_RUNBOOK.md §7.

DROP TABLE IF EXISTS default.traffic_service_1m_mv;
DROP TABLE IF EXISTS default.traffic_unknown_port_1m_mv;

SELECT 'migrate_port_service_rollups_ranges.sql: MVs dropped; use async rollups for new data' AS notice;
