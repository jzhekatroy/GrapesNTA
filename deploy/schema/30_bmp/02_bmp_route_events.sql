CREATE TABLE IF NOT EXISTS default.bmp_route_events
(
    `ts` DateTime64(6, 'UTC') CODEC(Delta(8), ZSTD(1)),
    `router_addr` FixedString(16),
    `peer_addr` FixedString(16),
    `peer_asn` UInt32,
    `event_type` LowCardinality(String),
    `family` UInt8,
    `prefix` FixedString(16),
    `prefix_len` UInt8,
    `next_hop` FixedString(16),
    `origin_asn` UInt32 DEFAULT 0,
    `as_path` Array(UInt32),
    `med` UInt32 DEFAULT 0,
    `local_pref` UInt32 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, peer_addr, prefix)
TTL toDateTime(ts) + toIntervalDay(180)
SETTINGS index_granularity = 8192;
