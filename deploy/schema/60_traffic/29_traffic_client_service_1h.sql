-- Cabinet showcase: client traffic by application service (hourly).
-- Unknown ports collapse to service_code='other'.
CREATE TABLE IF NOT EXISTS default.traffic_client_service_1h
(
    `hour` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `transport` LowCardinality(String),
    `service_code` LowCardinality(String),
    `service_name` String,
    `category` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64,
    INDEX idx_hour hour TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(hour)
ORDER BY (client_id, hour, source_id, direction, transport, category, service_code, service_name)
SETTINGS index_granularity = 8192;
