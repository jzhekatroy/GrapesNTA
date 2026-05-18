-- Editable VLAN classification map used by xdpflowd.
--
-- MVP rules:
--   * vlan_id is global (not scoped by sampler/interface);
--   * only the outer VLAN tag is used;
--   * kind controls local/remote classification:
--       customer/internal/mgmt/local -> local side
--       uplink/ix/peering/unknown    -> remote side

CREATE TABLE IF NOT EXISTS default.vlan_map
(
    vlan_id     UInt16,
    kind        LowCardinality(String),
    label       String,
    operator_id LowCardinality(String) DEFAULT '',
    source      LowCardinality(String) DEFAULT 'manual',
    enabled     UInt8,
    updated_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY vlan_id
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.vlan_map_enabled;

CREATE VIEW default.vlan_map_enabled AS
SELECT
    vlan_id,
    kind,
    label,
    operator_id,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        vlan_id,
        argMax(kind, updated_at) AS kind,
        argMax(label, updated_at) AS label,
        argMax(operator_id, updated_at) AS operator_id,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.vlan_map
    GROUP BY vlan_id
)
WHERE enabled_latest = 1;
