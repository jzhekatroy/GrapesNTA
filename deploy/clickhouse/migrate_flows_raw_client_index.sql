-- flows_raw: one skip index for the cabinet's client lookups.
--
-- The cabinet searches raw flows as "this client on either side", i.e.
-- src_client = X OR dst_client = X. A per-column index cannot decide such an OR
-- on its own — neither of the two bloom filters can reject a granule while the
-- other side might still match — so both columns go into a single set index that
-- evaluates the whole expression. set(0) keeps every distinct value per granule,
-- which is cheap here because both columns are LowCardinality.
--
-- No MATERIALIZE INDEX: flows_raw has a 6 day TTL, so existing parts age out and
-- newly inserted parts get the index right away. Until then those older parts are
-- simply read without granule skipping, which is correct, just not faster.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_flows_raw_client_index.sql

ALTER TABLE default.flows_raw DROP INDEX IF EXISTS idx_src_client;
ALTER TABLE default.flows_raw DROP INDEX IF EXISTS idx_dst_client;
ALTER TABLE default.flows_raw ADD INDEX IF NOT EXISTS idx_client (src_client, dst_client) TYPE set(0) GRANULARITY 4;
