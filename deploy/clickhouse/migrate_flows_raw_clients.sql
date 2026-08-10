-- Add cabinet-client columns to flows_raw.
-- Collector must be rebuilt/restarted after this migration so INSERT column lists match.
-- Safe to re-run.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_flows_raw_clients.sql

ALTER TABLE default.flows_raw
    ADD COLUMN IF NOT EXISTS src_client LowCardinality(String) DEFAULT '' AFTER dst_entity,
    ADD COLUMN IF NOT EXISTS dst_client LowCardinality(String) DEFAULT '' AFTER src_client;

ALTER TABLE default.flows_raw
    ADD INDEX IF NOT EXISTS idx_src_client src_client TYPE bloom_filter(0.01) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS idx_dst_client dst_client TYPE bloom_filter(0.01) GRANULARITY 4;
