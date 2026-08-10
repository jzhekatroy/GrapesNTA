-- Cabinet showcase: client traffic by remote IP country (hourly).
-- direction is from the client's point of view; country is the other side.
CREATE TABLE IF NOT EXISTS default.traffic_client_country_1h
(
    `hour` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `country_code` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (client_id, hour, source_id, direction, country_code)
SETTINGS index_granularity = 8192;
