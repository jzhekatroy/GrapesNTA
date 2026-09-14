-- Keep every live BMP announce (prefix + BGP next hop + path) in the origin
-- snapshot so ingest can pick the path of the hop the flow actually used.
-- Safe to re-run. Apply, then rebuild the snapshot (enrichment cron or
-- rebuild_bgp_origin_asn.py) and restart flowcollectord.
-- Existing tables keep their current ORDER BY; only new installs use
-- (family, prefix, next_hop). The view collapses to one origin per prefix
-- so bgp_origin_asn_dict (IP_TRIE) stays valid after the first rebuild.
--
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_bgp_next_hop.sql

ALTER TABLE default.bgp_prefix_origin_current
    ADD COLUMN IF NOT EXISTS next_hop String DEFAULT '' AFTER as_path;

ALTER TABLE default.bgp_prefix_origin_current_staging
    ADD COLUMN IF NOT EXISTS next_hop String DEFAULT '' AFTER as_path;

CREATE OR REPLACE VIEW default.bgp_prefix_origin_dict_src AS
SELECT
    prefix,
    any(origin_asn) AS origin_asn,
    any(peer_asn) AS peer_asn,
    max(active_paths) AS active_paths,
    any(source) AS source,
    max(snapshot_ts) AS snapshot_ts
FROM default.bgp_prefix_origin_current
GROUP BY prefix;
