CREATE TABLE IF NOT EXISTS default.net_flow_exclusions
(
    `rule_id` String,
    `prefix` String DEFAULT '',
    `family` UInt8 DEFAULT 0,
    `match_side` LowCardinality(String) DEFAULT 'any',
    `proto` UInt8 DEFAULT 0,
    `port_from` UInt16 DEFAULT 0,
    `port_to` UInt16 DEFAULT 0,
    `port_side` LowCardinality(String) DEFAULT 'any',
    `vlan_id` UInt16 DEFAULT 0,
    `switch_ip` String DEFAULT '',
    `if_index` UInt32 DEFAULT 0,
    `source_id` LowCardinality(String) DEFAULT '',
    `display_name` String DEFAULT '',
    `comment` String DEFAULT '',
    `enabled` UInt8,
    `source` LowCardinality(String) DEFAULT 'manual',
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY rule_id
SETTINGS index_granularity = 8192;
