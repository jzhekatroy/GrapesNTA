-- Latest BMP event per (router, peer, prefix), kept current by bmp_route_state_mv.
--
-- rebuild_bgp_origin_asn.py used to derive this by re-aggregating the whole
-- lookback window of bmp_route_events on every run. That window reached 460M
-- events while collapsing to under 8M distinct keys, so the rebuild spent
-- minutes of CPU rediscovering a state that barely changes between runs.
--
-- ReplacingMergeTree keeps the row with the highest ts per ORDER BY key, which
-- is exactly "what this peer last said about this prefix". Readers must still
-- aggregate with argMax(..., ts): replacement happens on merge, so freshly
-- inserted duplicates are visible until then.
--
-- TTL is deliberately longer than the default BGPORIGIN_LOOKBACK_DAYS=14 so a
-- longer lookback keeps working without losing prefixes.
CREATE TABLE IF NOT EXISTS default.bmp_route_state
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
    `as_path` Array(UInt32)
)
ENGINE = ReplacingMergeTree(ts)
PARTITION BY family
ORDER BY (family, prefix, prefix_len, router_addr, peer_addr)
TTL toDateTime(ts) + toIntervalDay(30)
SETTINGS index_granularity = 8192;
