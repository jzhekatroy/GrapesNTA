CREATE TABLE IF NOT EXISTS default.port_services
(
    `transport` LowCardinality(String),
    `port_from` UInt16,
    `port_to` UInt16,
    `service_code` LowCardinality(String),
    `service_name` String,
    `category` LowCardinality(String),
    `description` String DEFAULT '',
    `is_enabled` UInt8 DEFAULT 1,
    `updated_at` DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (transport, port_from, port_to)
SETTINGS index_granularity = 8192;
