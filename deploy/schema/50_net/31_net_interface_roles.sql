CREATE TABLE IF NOT EXISTS default.net_interface_roles
(
    `switch_ip` String,
    `if_index` UInt32,
    `boundary` LowCardinality(String) DEFAULT '',
    `connectivity` LowCardinality(String) DEFAULT '',
    `comment` String DEFAULT '',
    `updated_by` String DEFAULT '',
    `deleted` UInt8 DEFAULT 0,
    `updated_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (switch_ip, if_index)
SETTINGS index_granularity = 8192;
