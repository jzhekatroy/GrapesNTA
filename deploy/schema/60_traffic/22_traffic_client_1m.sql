-- Cabinet client traffic by minute.
-- direction is from the client's point of view: in = arrived at client, out = left client.
-- ORDER BY starts with client_id: the main query is "one client's traffic over a period".
-- The bucket column is therefore not a primary key prefix, so the rollup runner's
-- idempotency probe and its per-bucket DELETE need idx_minute to skip granules.
CREATE TABLE IF NOT EXISTS default.traffic_client_1m
(
    `minute` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64,
    INDEX idx_minute minute TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (client_id, minute, source_id, direction)
-- Per-minute detail is kept for two weeks, matching traffic_client_anomaly_1m:
-- long enough for a weekly baseline, short enough that minute rows do not pile
-- up forever. Depth lives in the hourly and daily tables.
TTL minute + toIntervalDay(14)
SETTINGS index_granularity = 8192;
