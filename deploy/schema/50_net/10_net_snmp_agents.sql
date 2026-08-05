CREATE TABLE IF NOT EXISTS default.net_snmp_agents
(
    `switch_ip` String,
    `display_name` String DEFAULT '',
    `source_ids` Array(String) DEFAULT [],
    `snmp_enabled` UInt8 DEFAULT 1,
    `community_override` String DEFAULT '',
    `port_override` UInt16 DEFAULT 0,
    `timeout_ms_override` UInt32 DEFAULT 0,
    `retries_override` UInt8 DEFAULT 0,
    `first_seen_at` DateTime('UTC'),
    `last_seen_at` DateTime('UTC'),
    `last_poll_at` DateTime('UTC') DEFAULT toDateTime(0, 'UTC'),
    `last_full_walk_at` DateTime('UTC') DEFAULT toDateTime(0, 'UTC'),
    `last_poll_status` LowCardinality(String) DEFAULT 'never',
    `last_poll_error` String DEFAULT '',
    `is_new` UInt8 DEFAULT 1,
    `updated_at` DateTime('UTC') DEFAULT now(),
    -- Last poll that actually answered. last_poll_at moves on failures too, so
    -- only this column tells whether the catalog is still trustworthy.
    `last_ok_at` DateTime('UTC') DEFAULT toDateTime(0, 'UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY switch_ip
SETTINGS index_granularity = 8192;
