CREATE TABLE IF NOT EXISTS default.bgp_updates_1m
(
    `minute` DateTime('UTC') CODEC(Delta(4), ZSTD(1)),
    `router_addr` FixedString(16),
    `peer_addr` FixedString(16),
    `announces` UInt64,
    `withdraws` UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, router_addr, peer_addr)
TTL minute + toIntervalDay(365)
SETTINGS index_granularity = 8192;
