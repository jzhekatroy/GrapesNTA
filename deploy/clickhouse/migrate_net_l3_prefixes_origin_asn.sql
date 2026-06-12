-- Add origin_asn to net_l3_prefixes for operator-owned ASN on local/customer prefixes.
-- Safe to re-run on existing deployments.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_net_l3_prefixes_origin_asn.sql

ALTER TABLE default.net_l3_prefixes
ADD COLUMN IF NOT EXISTS origin_asn UInt32 DEFAULT 0;

DROP VIEW IF EXISTS default.net_l3_prefixes_enabled;

CREATE VIEW default.net_l3_prefixes_enabled AS
SELECT
    prefix,
    family,
    entity_id,
    role,
    origin_asn,
    display_name,
    comment,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        prefix,
        family,
        argMax(entity_id, updated_at) AS entity_id,
        argMax(role, updated_at) AS role,
        argMax(origin_asn, updated_at) AS origin_asn,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_l3_prefixes
    GROUP BY
        family,
        prefix
)
WHERE enabled_latest = 1;
