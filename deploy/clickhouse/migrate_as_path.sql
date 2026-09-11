-- Store BGP AS path on the origin snapshot and on each ingested flow.
-- Classifier copies the path from bgp_prefix_origin_current at ingest time.
-- Safe to re-run. Apply BEFORE restarting flowcollectord / xdpflowd that INSERT
-- src_as_path / dst_as_path. Then rebuild the origin snapshot (enrichment cron
-- or rebuild_bgp_origin_asn.py) so new flows get a non-empty path.
--
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_as_path.sql

ALTER TABLE default.bgp_prefix_origin_current
    ADD COLUMN IF NOT EXISTS as_path Array(UInt32) DEFAULT [] AFTER snapshot_ts;

ALTER TABLE default.bgp_prefix_origin_current_staging
    ADD COLUMN IF NOT EXISTS as_path Array(UInt32) DEFAULT [] AFTER snapshot_ts;

ALTER TABLE default.flows_raw
    ADD COLUMN IF NOT EXISTS src_as_path Array(UInt32) DEFAULT [] AFTER dst_asn,
    ADD COLUMN IF NOT EXISTS dst_as_path Array(UInt32) DEFAULT [] AFTER src_as_path;
