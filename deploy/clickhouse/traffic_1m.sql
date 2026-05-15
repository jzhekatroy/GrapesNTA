-- Minute-level traffic aggregate for dashboard charts.
--
-- This deployment does not use default.local_networks_dict because the remote
-- ClickHouse rejects dictionary DDL through the SQL proxy. The materialized
-- view therefore writes direction='unknown' for every minute. Real
-- in / out / internal / transit classification is computed on the fly in
-- API queries that JOIN flows_raw with default.local_networks_enabled. See
-- docs/LOCAL_NETWORKS_DIRECTION.md for ready-to-use SQL.
--
-- Apply after:
--   1. default.flows_raw exists;
--   2. deploy/clickhouse/local_networks.sql was applied (table + view).
--
-- When dictHas becomes available again (XML dictionary installed on the CH
-- host), this view can be redeployed to populate direction directly from
-- default.local_networks_dict for both IPv4 and IPv6 flows. The template for
-- that variant lives at the bottom of this file as a comment.

CREATE TABLE IF NOT EXISTS default.traffic_1m
(
    minute      DateTime('UTC') CODEC(Delta, ZSTD(1)),
    direction   LowCardinality(String), -- in / out / internal / transit / unknown
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, direction)
TTL minute + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS default.traffic_1m_mv
TO default.traffic_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    'unknown'                         AS direction,
    sum(bytes)                        AS bytes,
    sum(packets)                      AS packets,
    count()                           AS flows_count
FROM default.flows_raw
GROUP BY minute;

-- Future variant once default.local_networks_dict is available on the CH host:
--
-- CREATE MATERIALIZED VIEW IF NOT EXISTS default.traffic_1m_mv
-- TO default.traffic_1m
-- AS
-- SELECT
--     minute,
--     direction,
--     sum(bytes) AS bytes,
--     sum(packets) AS packets,
--     count() AS flows_count
-- FROM
-- (
--     SELECT
--         minute,
--         multiIf(
--             src_is_local AND dst_is_local, 'internal',
--             src_is_local AND NOT dst_is_local, 'out',
--             NOT src_is_local AND dst_is_local, 'in',
--             'transit'
--         ) AS direction,
--         bytes,
--         packets
--     FROM
--     (
--         SELECT
--             toStartOfMinute(time_received_ns) AS minute,
--             multiIf(
--                 etype = 0x0800, dictHas('default.local_networks_dict', tuple(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))))),
--                 etype = 0x86DD, dictHas('default.local_networks_dict', tuple(reinterpretAsIPv6(src_addr))),
--                 0
--             ) AS src_is_local,
--             multiIf(
--                 etype = 0x0800, dictHas('default.local_networks_dict', tuple(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))),
--                 etype = 0x86DD, dictHas('default.local_networks_dict', tuple(reinterpretAsIPv6(dst_addr))),
--                 0
--             ) AS dst_is_local,
--             bytes,
--             packets
--         FROM default.flows_raw
--     )
-- )
-- GROUP BY minute, direction;
