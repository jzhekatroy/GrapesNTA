CREATE TABLE IF NOT EXISTS default.traffic_pair_1h
(
    `hour` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `src_ip` String,
    `dst_ip` String,
    `src_asn` UInt32,
    `dst_asn` UInt32,
    `src_as_name` String,
    `dst_as_name` String,
    `src_ip_country` LowCardinality(String),
    `dst_ip_country` LowCardinality(String),
    `src_as_country` LowCardinality(String),
    `dst_as_country` LowCardinality(String),
    `src_scope` LowCardinality(String),
    `dst_scope` LowCardinality(String),
    `src_label` String,
    `dst_label` String,
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(hour)
ORDER BY (
    hour,
    source_id,
    direction,
    src_ip,
    dst_ip,
    src_asn,
    dst_asn,
    src_ip_country,
    dst_ip_country
)
TTL hour + toIntervalDay(90)
SETTINGS index_granularity = 8192;
