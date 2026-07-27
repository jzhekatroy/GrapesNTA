CREATE TABLE IF NOT EXISTS default.net_interface_roles_effective
(
    `switch_ip` String,
    `if_index` UInt32,
    `boundary` LowCardinality(String) DEFAULT 'unknown',
    `boundary_source` LowCardinality(String) DEFAULT 'default',
    `boundary_rule_id` String DEFAULT '',
    `connectivity` LowCardinality(String) DEFAULT '',
    `connectivity_source` LowCardinality(String) DEFAULT 'default',
    `connectivity_rule_id` String DEFAULT '',
    `updated_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (switch_ip, if_index)
SETTINGS index_granularity = 8192;
