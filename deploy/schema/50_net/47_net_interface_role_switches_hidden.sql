CREATE TABLE IF NOT EXISTS default.net_interface_role_switches_hidden
(
    `switch_ip` String,
    `display_name` String DEFAULT '',
    `hidden` UInt8 DEFAULT 0,
    `updated_by` String DEFAULT '',
    `updated_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (switch_ip)
SETTINGS index_granularity = 8192;
