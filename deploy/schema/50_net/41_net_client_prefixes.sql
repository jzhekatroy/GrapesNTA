-- Prefixes attached to a client when bind_mode = 'prefixes'.
-- A prefix may belong to at most one enabled client (enforced in admin API later).
CREATE TABLE IF NOT EXISTS default.net_client_prefixes
(
    `client_id` LowCardinality(String),
    `prefix` String,
    `family` UInt8,
    `enabled` UInt8,
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;
