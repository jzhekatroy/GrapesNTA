CREATE TABLE IF NOT EXISTS default.observation_rollups_5m
(
    `observation_id` String,
    `minute` DateTime,
    `dim0` LowCardinality(String) DEFAULT '',
    `dim1` LowCardinality(String) DEFAULT '',
    `bytes` UInt64,
    `packets` UInt64,
    `flows` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (observation_id, minute, dim0, dim1)
TTL minute + toIntervalDay(14)
SETTINGS index_granularity = 8192;
