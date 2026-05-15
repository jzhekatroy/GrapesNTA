-- BMP/BGP storage for bmpgrapes (run once on ClickHouse).
--
-- Two append-only tables and one 1-minute aggregate. Tables intentionally
-- mirror the flows_raw style: FixedString(16) for IPs (IPv4-in-first-4-bytes
-- when family=4) and partition by date for cheap retention.

CREATE TABLE IF NOT EXISTS default.bmp_peers
(
    ts                   DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
    router_addr          FixedString(16),
    peer_addr            FixedString(16),
    peer_asn             UInt32,
    peer_type            UInt8,
    is_ipv6              UInt8,
    state                LowCardinality(String),     -- 'up' / 'down'
    reason               LowCardinality(String) DEFAULT '',
    local_asn            UInt32 DEFAULT 0,
    local_addr           FixedString(16),
    hold_time            UInt16 DEFAULT 0,
    negotiated_hold_time UInt16 DEFAULT 0,
    bgp_id               UInt32 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, router_addr, peer_addr)
TTL toDateTime(ts) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.bmp_route_events
(
    ts          DateTime64(6, 'UTC') CODEC(Delta, ZSTD(1)),
    router_addr FixedString(16),
    peer_addr   FixedString(16),
    peer_asn    UInt32,
    event_type  LowCardinality(String),               -- 'announce' / 'withdraw'
    family      UInt8,                                -- 4 (IPv4) or 6 (IPv6)
    prefix      FixedString(16),
    prefix_len  UInt8,
    next_hop    FixedString(16),
    origin_asn  UInt32 DEFAULT 0,
    as_path     Array(UInt32),
    med         UInt32 DEFAULT 0,
    local_pref  UInt32 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, peer_addr, prefix)
TTL toDateTime(ts) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- Per-minute aggregate of announces/withdraws per (router, peer).
--
-- IMPORTANT: this table is intentionally NOT fed by a Materialized View on the
-- bmp_route_events insert path. Initial full RIB dumps from a router (hundreds
-- of thousands of NLRI in a few seconds) made the per-insert MV blow past
-- ClickHouse memory limits, which in turn caused bmpgrapes to drop rows.
--
-- For the MVP, dashboards can either:
--   1) query bmp_route_events directly with GROUP BY toStartOfMinute(ts)
--      (cheap enough for short windows), OR
--   2) populate this aggregate periodically via a scheduled INSERT SELECT,
--      e.g. once a minute over the last completed minute (small batch, no
--      pressure on the hot path).
--
-- Example periodic backfill (idempotent within the chosen partition window):
--
--   INSERT INTO default.bgp_updates_1m
--   SELECT
--       toStartOfMinute(ts) AS minute,
--       router_addr,
--       peer_addr,
--       countIf(event_type = 'announce') AS announces,
--       countIf(event_type = 'withdraw') AS withdraws
--   FROM default.bmp_route_events
--   WHERE ts >= toStartOfMinute(now() - INTERVAL 2 MINUTE)
--     AND ts <  toStartOfMinute(now())
--   GROUP BY minute, router_addr, peer_addr;
--
-- If an old environment already has default.bgp_updates_1m_mv, drop it:
--   DROP TABLE IF EXISTS default.bgp_updates_1m_mv;

CREATE TABLE IF NOT EXISTS default.bgp_updates_1m
(
    minute       DateTime('UTC') CODEC(Delta, ZSTD(1)),
    router_addr  FixedString(16),
    peer_addr    FixedString(16),
    announces    UInt64,
    withdraws    UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, router_addr, peer_addr)
TTL minute + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;
