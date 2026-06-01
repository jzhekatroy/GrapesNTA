-- Add source_id to high-volume raw tables.
--
-- Apply before restarting xdpflowd / dnsflowd with -source-id:
--   clickhouse-client ... --multiquery < deploy/clickhouse/flows_raw_source_id.sql

ALTER TABLE default.flows_raw
    ADD COLUMN IF NOT EXISTS source_id LowCardinality(String) DEFAULT 'xdp-default';

ALTER TABLE default.dns_log
    ADD COLUMN IF NOT EXISTS source_id LowCardinality(String) DEFAULT 'dns-default';

ALTER TABLE default.dns_answers
    ADD COLUMN IF NOT EXISTS source_id LowCardinality(String) DEFAULT 'dns-default';
