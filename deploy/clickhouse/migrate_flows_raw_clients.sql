-- Add cabinet-client columns to flows_raw.
-- Collector must be rebuilt/restarted after this migration so INSERT column lists match.
-- Safe to re-run.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_flows_raw_clients.sql

ALTER TABLE default.flows_raw
    ADD COLUMN IF NOT EXISTS src_client LowCardinality(String) DEFAULT '' AFTER dst_entity,
    ADD COLUMN IF NOT EXISTS dst_client LowCardinality(String) DEFAULT '' AFTER src_client;

-- One index over both columns: the cabinet looks a client up on either side, and
-- a per-column index cannot decide that OR alone. See
-- deploy/clickhouse/migrate_flows_raw_client_index.sql for installs that already
-- got the two per-column bloom filters.
ALTER TABLE default.flows_raw
    ADD INDEX IF NOT EXISTS idx_client (src_client, dst_client) TYPE set(0) GRANULARITY 4;
