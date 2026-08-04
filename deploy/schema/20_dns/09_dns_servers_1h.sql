CREATE TABLE IF NOT EXISTS default.dns_servers_1h
(
    `hour` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `server_ip` FixedString(16),
    `queries` UInt64,
    `responses` UInt64,
    `nxdomain` UInt64,
    `servfail` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, source_id, server_ip)
TTL hour + toIntervalDay(90)
SETTINGS index_granularity = 8192;
