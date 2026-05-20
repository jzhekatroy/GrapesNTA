-- Editable VLAN attachment map used by xdpflowd.
--
-- MVP rules:
--   * vlan_id is global (not scoped by sampler/interface);
--   * only the outer VLAN tag is used;
--   * VLAN describes the attachment/context where a packet was seen, not IP
--     ownership. Direction is calculated from endpoint_scope (ASN/prefix),
--     while VLAN fills src/dst_attachment_* columns.

CREATE TABLE IF NOT EXISTS default.vlan_map
(
    vlan_id     UInt16,
    -- Deprecated compatibility column. New rows should fill attachment_kind.
    kind        LowCardinality(String) DEFAULT '',
    attachment_kind LowCardinality(String) DEFAULT '',
    boundary    LowCardinality(String) DEFAULT 'unknown',
    label       String,
    operator_id LowCardinality(String) DEFAULT '',
    source      LowCardinality(String) DEFAULT 'manual',
    enabled     UInt8,
    updated_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY vlan_id
SETTINGS index_granularity = 8192;

ALTER TABLE default.vlan_map
ADD COLUMN IF NOT EXISTS kind LowCardinality(String) DEFAULT '' AFTER vlan_id,
ADD COLUMN IF NOT EXISTS attachment_kind LowCardinality(String) DEFAULT '' AFTER kind,
ADD COLUMN IF NOT EXISTS boundary LowCardinality(String) DEFAULT 'unknown' AFTER attachment_kind;

DROP TABLE IF EXISTS default.vlan_map_enabled;

CREATE VIEW default.vlan_map_enabled AS
SELECT
    vlan_id,
    attachment_kind,
    multiIf(
        boundary_raw IN ('internal', 'external'), boundary_raw,
        attachment_kind IN ('local', 'customer', 'internal', 'mgmt', 'core'), 'internal',
        attachment_kind IN ('uplink', 'ix', 'peering', 'transit', 'pni', 'ppni'), 'external',
        'unknown'
    ) AS boundary,
    label,
    operator_id,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        vlan_id,
        if(argMax(attachment_kind, updated_at) != '', argMax(attachment_kind, updated_at), argMax(kind, updated_at)) AS attachment_kind,
        argMax(boundary, updated_at) AS boundary_raw,
        argMax(label, updated_at) AS label,
        argMax(operator_id, updated_at) AS operator_id,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.vlan_map
    GROUP BY vlan_id
)
WHERE enabled_latest = 1;
