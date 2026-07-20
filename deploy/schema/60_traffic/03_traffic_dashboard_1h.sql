CREATE TABLE IF NOT EXISTS default.traffic_dashboard_1h
(
    `hour` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `total_bytes` UInt64,
    `in_bytes` UInt64,
    `out_bytes` UInt64,
    `transit_bytes` UInt64,
    `internal_bytes` UInt64,
    `unknown_bytes` UInt64,
    `total_packets` UInt64,
    `in_packets` UInt64,
    `out_packets` UInt64,
    `transit_packets` UInt64,
    `internal_packets` UInt64,
    `unknown_packets` UInt64,
    `total_flows` UInt64,
    `in_flows` UInt64,
    `out_flows` UInt64,
    `transit_flows` UInt64,
    `internal_flows` UInt64,
    `unknown_flows` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, source_id)
SETTINGS index_granularity = 8192;
