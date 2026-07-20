CREATE TABLE IF NOT EXISTS default.net_snmp_settings
(
    `settings_id` String DEFAULT 'global',
    `community` String DEFAULT '',
    `port` UInt16 DEFAULT 161,
    `timeout_ms` UInt32 DEFAULT 2000,
    `retries` UInt8 DEFAULT 1,
    `discover_lookback_hours` UInt16 DEFAULT 24,
    `refresh_interval_sec` UInt32 DEFAULT 1800,
    `full_walk_interval_sec` UInt32 DEFAULT 21600,
    `enabled` UInt8 DEFAULT 1,
    `updated_at` DateTime('UTC') DEFAULT now(),
    `auto_enable_new_agents` UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY settings_id
SETTINGS index_granularity = 8192;
