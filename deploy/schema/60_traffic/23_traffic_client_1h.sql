-- Daily partitions keep the rollup runner's per-bucket DELETE from rewriting a
-- whole month, and idx_hour scopes it (and the idempotency probe) to the
-- granules of that hour, since the bucket column is not a primary key prefix.
CREATE TABLE IF NOT EXISTS default.traffic_client_1h
(
    `hour` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64,
    INDEX idx_hour hour TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(hour)
ORDER BY (client_id, hour, source_id, direction)
SETTINGS index_granularity = 8192;
