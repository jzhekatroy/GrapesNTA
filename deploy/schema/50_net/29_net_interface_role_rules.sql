CREATE TABLE IF NOT EXISTS default.net_interface_role_rules
(
    `rule_id` String,
    `priority` UInt32 DEFAULT 100,
    `match_field` LowCardinality(String) DEFAULT 'descr',
    `pattern` String DEFAULT '',
    `case_sensitive` UInt8 DEFAULT 0,
    `min_speed_mbps` UInt32 DEFAULT 0,
    `max_speed_mbps` UInt32 DEFAULT 0,
    `boundary` LowCardinality(String) DEFAULT '',
    `connectivity` LowCardinality(String) DEFAULT '',
    `comment` String DEFAULT '',
    `enabled` UInt8 DEFAULT 1,
    `deleted` UInt8 DEFAULT 0,
    `updated_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY rule_id
SETTINGS index_granularity = 8192;
