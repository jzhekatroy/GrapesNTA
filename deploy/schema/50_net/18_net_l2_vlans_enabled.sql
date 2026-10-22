CREATE OR REPLACE VIEW default.net_l2_vlans_enabled
(
    `vlan_id` UInt16,
    `entity_id` String,
    `attachment_type` String,
    `boundary` String,
    `display_name` String,
    `comment` String,
    `ix` UInt8,
    `ix_location` String,
    `source` String,
    `updated_at` DateTime
)
AS SELECT
    vlan_id,
    entity_id,
    attachment_type,
    multiIf(boundary_raw IN ('internal', 'external'), boundary_raw, attachment_type IN ('customer', 'internal', 'core'), 'internal', attachment_type IN ('uplink', 'ix', 'peering'), 'external', 'unknown') AS boundary,
    display_name,
    comment,
    ix,
    ix_location,
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
        argMax(ix, updated_at) AS ix,
        argMax(ix_location, updated_at) AS ix_location,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_l2_vlans
    GROUP BY vlan_id
)
WHERE enabled_latest = 1;
