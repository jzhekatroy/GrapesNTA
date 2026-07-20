CREATE TABLE IF NOT EXISTS default.dns_answers
(
    `ts` DateTime64(6, 'UTC') CODEC(Delta(8), ZSTD(1)),
    `source_id` LowCardinality(String) DEFAULT 'dns-default',
    `sampler_address` FixedString(16),
    `client_ip` FixedString(16),
    `server_ip` FixedString(16),
    `client_port` UInt16,
    `server_port` UInt16,
    `query_name` String,
    `qtype` LowCardinality(String),
    `qclass` LowCardinality(String) DEFAULT 'IN',
    `answer_type` LowCardinality(String),
    `answer_ip` FixedString(16),
    `ttl` UInt32,
    `rcode` UInt8,
    `txid` UInt16,
    `transport` LowCardinality(String) DEFAULT 'udp'
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (client_ip, answer_ip, ts)
TTL toDateTime(ts) + toIntervalDay(30)
SETTINGS index_granularity = 8192;
