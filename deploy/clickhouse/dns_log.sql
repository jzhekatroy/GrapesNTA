-- DNS log for dnsflowd (run once on ClickHouse).
-- One row per parsed DNS query or response (is_response).

CREATE TABLE IF NOT EXISTS default.dns_log
(
    ts                  DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
    source_id           LowCardinality(String) DEFAULT 'dns-default',
    sampler_address     FixedString(16),

    client_ip           FixedString(16),
    server_ip           FixedString(16),
    client_port         UInt16,
    server_port         UInt16,
    is_response         UInt8,
    transport           LowCardinality(String) DEFAULT 'udp',

    txid                UInt16,
    rcode               UInt8,
    truncated           UInt8,
    recursion_desired   UInt8,
    recursion_available UInt8,

    query_name          String,
    qtype               LowCardinality(String),
    qclass              LowCardinality(String) DEFAULT 'IN',

    answers_a           Array(FixedString(16)),
    answers_aaaa        Array(FixedString(16)),
    answers_cname       Array(String),
    answer_ttls         Array(UInt32),
    answer_count        UInt16,

    raw_size            UInt16
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, client_ip)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;
