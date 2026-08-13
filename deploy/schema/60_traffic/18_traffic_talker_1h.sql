CREATE TABLE IF NOT EXISTS default.traffic_talker_1h
(
    `hour` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `endpoint_side` LowCardinality(String),
    `direction` LowCardinality(String),
    `endpoint_ip` String,
    `endpoint_asn` UInt32,
    `endpoint_as_name` String,
    `endpoint_ip_country` LowCardinality(String),
    `endpoint_as_country` LowCardinality(String),
    `endpoint_scope` LowCardinality(String),
    `endpoint_label` String,
    `endpoint_network_name` String,
    `endpoint_network_role` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(hour)
ORDER BY (
    hour,
    source_id,
    endpoint_side,
    direction,
    endpoint_ip,
    endpoint_asn,
    endpoint_ip_country,
    endpoint_as_country,
    endpoint_scope,
    endpoint_network_role
)
TTL hour + toIntervalDay(90)
SETTINGS index_granularity = 8192;
