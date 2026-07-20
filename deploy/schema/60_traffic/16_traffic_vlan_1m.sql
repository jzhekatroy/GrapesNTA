CREATE TABLE IF NOT EXISTS default.traffic_vlan_1m
(
    `minute` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `attachment_type` LowCardinality(String),
    `vlan_id` UInt16,
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, direction, attachment_type, vlan_id)
SETTINGS index_granularity = 8192;
