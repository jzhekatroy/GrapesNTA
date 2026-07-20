CREATE TABLE IF NOT EXISTS default.traffic_country_1m
(
    `minute` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `country_basis` LowCardinality(String),
    `country_side` LowCardinality(String),
    `direction` LowCardinality(String),
    `country_code` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, country_basis, country_side, direction, country_code)
SETTINGS index_granularity = 8192;
