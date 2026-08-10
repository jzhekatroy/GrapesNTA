-- Cabinet showcase: client traffic by remote ASN (hourly).
-- is_total=1 holds the full bucket total so UI can show "Прочие" = total - sum(top).
-- Detail rows keep the top-N ASN by bytes (see rollup job).
CREATE TABLE IF NOT EXISTS default.traffic_client_asn_1h
(
    `hour` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `is_total` UInt8,
    `remote_asn` UInt32,
    `remote_as_name` String,
    `remote_as_country` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (client_id, hour, source_id, direction, is_total, remote_asn)
SETTINGS index_granularity = 8192;
