CREATE TABLE IF NOT EXISTS default.dns_clients_1h
(
    `hour` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `client_ip` FixedString(16),
    `queries` SimpleAggregateFunction(sum, UInt64),
    `responses` SimpleAggregateFunction(sum, UInt64),
    `nxdomain` SimpleAggregateFunction(sum, UInt64),
    `servfail` SimpleAggregateFunction(sum, UInt64),
    `unique_domains_state` AggregateFunction(uniqCombined, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, source_id, client_ip)
TTL hour + toIntervalDay(90)
SETTINGS index_granularity = 8192;
