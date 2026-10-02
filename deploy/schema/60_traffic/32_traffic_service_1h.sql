-- Hourly sum of traffic_service_1m. The overview reads this for windows of
-- 24h and longer; the minute table stays the source for shorter ranges and
-- for the hours the rollup has not caught up to yet.
CREATE TABLE IF NOT EXISTS default.traffic_service_1h
(
    `hour` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `proto` UInt32,
    `transport` LowCardinality(String),
    `service_side` LowCardinality(String),
    `service_port` UInt16,
    `service_code` LowCardinality(String),
    `service_name` String,
    `category` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, source_id, direction, transport, category, service_code, service_name, service_port, service_side, proto)
SETTINGS index_granularity = 8192;
