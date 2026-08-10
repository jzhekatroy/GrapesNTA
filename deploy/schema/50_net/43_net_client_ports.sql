-- Exporter ports attached to a client when bind_mode = 'ports'.
-- Key: sampler (switch) IP + ifIndex. A port may belong to at most one enabled client.
CREATE TABLE IF NOT EXISTS default.net_client_ports
(
    `client_id` LowCardinality(String),
    `switch_ip` String,
    `if_index` UInt32,
    `comment` String DEFAULT '',
    `enabled` UInt8,
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (switch_ip, if_index)
SETTINGS index_granularity = 8192;
