CREATE TABLE IF NOT EXISTS default.net_interfaces
(
    `switch_ip` String,
    `if_index` UInt32,
    `if_name` String DEFAULT '',
    `if_alias` String DEFAULT '',
    `if_descr` String DEFAULT '',
    `if_high_speed_mbps` UInt32 DEFAULT 0,
    `if_speed_bps` UInt64 DEFAULT 0,
    `updated_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (switch_ip, if_index)
SETTINGS index_granularity = 8192;
