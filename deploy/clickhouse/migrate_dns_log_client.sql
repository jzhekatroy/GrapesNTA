-- Add the cabinet-client column to dns_log.
-- Apply BEFORE rebuilding dnsflowd: the raw INSERT lists columns explicitly, so
-- an old binary keeps working against the new schema, while a new binary against
-- the old schema fails every batch.
-- Safe to re-run.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_dns_log_client.sql

ALTER TABLE default.dns_log
    ADD COLUMN IF NOT EXISTS client_id LowCardinality(String) DEFAULT '' AFTER client_ip;

-- The cabinet always filters by one client, and client_id is not part of the
-- sort key, so a set index is what keeps those queries from reading the whole
-- retention. Unlike flows_raw there is only one side to look at here.
ALTER TABLE default.dns_log
    ADD INDEX IF NOT EXISTS idx_dns_client client_id TYPE set(0) GRANULARITY 4;

-- Existing rows stay empty: the client is resolved at capture time and cannot be
-- reconstructed afterwards without guessing who owned the address back then.
