-- Daily roll-up of traffic_client_service_1h. Same service_code / service_port /
-- port_owner semantics: see 29_traffic_client_service_1h.sql.
CREATE TABLE IF NOT EXISTS default.traffic_client_service_1d
(
    `day` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `transport` LowCardinality(String),
    `service_code` LowCardinality(String),
    `service_name` String,
    `category` LowCardinality(String),
    `service_port` UInt16,
    `port_owner` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64,
    INDEX idx_day day TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (client_id, day, source_id, direction, transport, category, service_code, service_name, service_port, port_owner)
TTL day + toIntervalDay(730)
SETTINGS index_granularity = 8192;
