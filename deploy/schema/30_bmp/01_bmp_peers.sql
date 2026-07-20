CREATE TABLE IF NOT EXISTS default.bmp_peers
(
    `ts` DateTime64(6, 'UTC') CODEC(Delta(8), ZSTD(1)),
    `router_addr` FixedString(16),
    `peer_addr` FixedString(16),
    `peer_asn` UInt32,
    `peer_type` UInt8,
    `is_ipv6` UInt8,
    `state` LowCardinality(String),
    `reason` LowCardinality(String) DEFAULT '',
    `local_asn` UInt32 DEFAULT 0,
    `local_addr` FixedString(16),
    `hold_time` UInt16 DEFAULT 0,
    `negotiated_hold_time` UInt16 DEFAULT 0,
    `bgp_id` UInt32 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, router_addr, peer_addr)
TTL toDateTime(ts) + toIntervalDay(365)
SETTINGS index_granularity = 8192;
