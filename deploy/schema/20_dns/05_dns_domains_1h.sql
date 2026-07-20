CREATE TABLE IF NOT EXISTS default.dns_domains_1h
(
    `hour` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `query_name` String,
    `qtype` LowCardinality(String),
    `queries` UInt64,
    `responses` UInt64,
    `nxdomain` UInt64,
    `servfail` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, source_id, query_name, qtype)
TTL hour + toIntervalDay(90)
SETTINGS index_granularity = 8192;
