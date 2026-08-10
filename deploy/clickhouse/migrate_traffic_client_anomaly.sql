-- Per-minute client profile for anomaly and DDoS detection.
-- Mirrors deploy/schema/60_traffic/31_traffic_client_anomaly_1m.sql.
-- Safe to re-run.

CREATE TABLE IF NOT EXISTS default.traffic_client_anomaly_1m
(
    `minute` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `transport` LowCardinality(String),
    `bytes` SimpleAggregateFunction(sum, UInt64),
    `packets` SimpleAggregateFunction(sum, UInt64),
    `flows_count` SimpleAggregateFunction(sum, UInt64),
    `syn_flows` SimpleAggregateFunction(sum, UInt64),
    `remote_ips_state` AggregateFunction(uniqCombined, FixedString(16)),
    INDEX idx_minute minute TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (client_id, minute, source_id, direction, transport)
TTL minute + toIntervalDay(14)
SETTINGS index_granularity = 8192;
