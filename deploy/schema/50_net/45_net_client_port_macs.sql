-- MAC addresses ERP lists on a client port. Safe to re-run. No DROP.
-- One port keeps many MACs. A MAC claimed by several accounts is not written.

CREATE TABLE IF NOT EXISTS default.net_client_port_macs
(
    `client_id` LowCardinality(String),
    `switch_ip` String,
    `if_index` UInt32,
    `mac` String,
    `enabled` UInt8,
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (switch_ip, if_index, mac)
SETTINGS index_granularity = 8192;
