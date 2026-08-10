-- Operator customers (cabinet clients). Independent from net_entities (L3 owners).
-- bind_mode: 'prefixes' | 'ports' — exactly one attachment method per client.
CREATE TABLE IF NOT EXISTS default.net_clients
(
    `client_id` LowCardinality(String),
    `display_name` String,
    `comment` String DEFAULT '',
    `bind_mode` LowCardinality(String) DEFAULT 'prefixes',
    `enabled` UInt8,
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY client_id
SETTINGS index_granularity = 8192;
