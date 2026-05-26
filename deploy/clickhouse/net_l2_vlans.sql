-- L2 VLAN attachment map: customer | uplink | ix | peering | core | internal | unknown.
--
-- Apply after net_entities.sql:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_l2_vlans.sql

CREATE TABLE IF NOT EXISTS default.net_l2_vlans
(
    vlan_id          UInt16,
    entity_id        LowCardinality(String) DEFAULT '',
    attachment_type  LowCardinality(String) DEFAULT 'unknown',
    boundary         LowCardinality(String) DEFAULT 'unknown',
    display_name     String DEFAULT '',
    comment          String DEFAULT '',
    enabled          UInt8,
    source           LowCardinality(String) DEFAULT 'manual',
    updated_at       DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY vlan_id
SETTINGS index_granularity = 8192;

DROP VIEW IF EXISTS default.net_l2_vlans_enabled;

CREATE VIEW default.net_l2_vlans_enabled AS
SELECT
    vlan_id,
    entity_id,
    attachment_type,
    multiIf(
        boundary_raw IN ('internal', 'external'), boundary_raw,
        attachment_type IN ('customer', 'internal', 'core'), 'internal',
        attachment_type IN ('uplink', 'ix', 'peering'), 'external',
        'unknown'
    ) AS boundary,
    display_name,
    comment,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        vlan_id,
        argMax(entity_id, updated_at) AS entity_id,
        argMax(attachment_type, updated_at) AS attachment_type,
        argMax(boundary, updated_at) AS boundary_raw,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_l2_vlans
    GROUP BY vlan_id
)
WHERE enabled_latest = 1;
