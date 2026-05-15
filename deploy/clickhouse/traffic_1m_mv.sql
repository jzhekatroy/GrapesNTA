-- Minute-level traffic aggregate materialized view.
--
-- This deployment does not use default.local_networks_dict because the remote
-- ClickHouse rejects dictionary DDL through the SQL proxy. The MV therefore
-- writes direction='unknown' for every minute. Real in / out / internal /
-- transit classification is computed on the fly in API queries that JOIN
-- flows_raw with default.local_networks_enabled. See
-- docs/LOCAL_NETWORKS_DIRECTION.md for ready-to-use SQL.
--
-- Apply after:
--   1. default.flows_raw exists;
--   2. deploy/clickhouse/traffic_1m_table.sql was applied;
--   3. deploy/clickhouse/local_networks.sql was applied (table + view).
--
-- Compatible with old clickhouse-client (18.x) without --multiquery: pipe
-- the file or pass it via --query "$(cat ...)". Drop the existing MV first
-- with DROP TABLE IF EXISTS default.traffic_1m_mv.

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
GROUP BY minute

-- Future variant once default.local_networks_dict is available on the CH host.
-- Notes:
--   * IPv6 cast uses CAST(addr AS IPv6) (ClickHouse 24.x): the legacy
--     reinterpretAsIPv6 was removed in 24.x and the function is not available
--     on the production server.
--   * dictHas takes an IPv4/IPv6-typed key for IP_TRIE dictionaries.
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
--                 etype = 0x86DD, dictHas('default.local_networks_dict', tuple(CAST(src_addr AS IPv6))),
--                 0
--             ) AS src_is_local,
--             multiIf(
--                 etype = 0x0800, dictHas('default.local_networks_dict', tuple(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))),
--                 etype = 0x86DD, dictHas('default.local_networks_dict', tuple(CAST(dst_addr AS IPv6))),
--                 0
--             ) AS dst_is_local,
--             bytes,
--             packets
--         FROM default.flows_raw
--     )
-- )
-- GROUP BY minute, direction
