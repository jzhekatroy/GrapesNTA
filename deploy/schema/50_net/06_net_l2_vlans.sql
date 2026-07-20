CREATE TABLE IF NOT EXISTS default.net_l2_vlans
(
    `vlan_id` UInt16,
    `entity_id` LowCardinality(String) DEFAULT '',
    `attachment_type` LowCardinality(String) DEFAULT 'unknown',
    `boundary` LowCardinality(String) DEFAULT 'unknown',
    `display_name` String DEFAULT '',
    `comment` String DEFAULT '',
    `enabled` UInt8,
    `source` LowCardinality(String) DEFAULT 'manual',
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY vlan_id
SETTINGS index_granularity = 8192;
