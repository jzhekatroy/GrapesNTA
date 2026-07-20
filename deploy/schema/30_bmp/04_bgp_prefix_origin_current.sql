CREATE TABLE IF NOT EXISTS default.bgp_prefix_origin_current
(
    `prefix` String,
    `family` UInt8,
    `origin_asn` UInt32,
    `peer_asn` UInt32,
    `active_paths` UInt32,
    `last_ts` DateTime64(6, 'UTC'),
    `source` LowCardinality(String),
    `snapshot_ts` DateTime
)
ENGINE = MergeTree
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;
