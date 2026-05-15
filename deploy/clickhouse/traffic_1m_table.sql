-- Minute-level traffic aggregate table for dashboard charts.
--
-- Apply once, before traffic_1m_mv.sql. The DDL uses CODEC(Delta, ZSTD(1))
-- and TTL, so it is NOT compatible with --multiquery on old clickhouse-client
-- (e.g. 18.16.x). Pass this file via --query "$(cat ...)" or pipe it without
-- --multiquery so the server (24.x) does the parsing.

CREATE TABLE IF NOT EXISTS default.traffic_1m
(
    minute      DateTime('UTC') CODEC(Delta, ZSTD(1)),
    direction   LowCardinality(String),
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, direction)
TTL minute + INTERVAL 365 DAY
SETTINGS index_granularity = 8192
