-- Minute-level traffic aggregate for dashboard charts.
--
-- Apply after:
--   1. default.flows_raw exists;
--   2. deploy/clickhouse/local_networks.sql was applied;
--   3. default.local_networks_dict was created by
--      scripts/load_local_networks_from_asn.py.
--
-- Direction is classified with local_networks_dict:
--   src local, dst external -> out
--   src external, dst local -> in
--   src local, dst local    -> internal
--   external/external       -> transit
--
-- If local_networks_dict is empty, all traffic becomes transit. For an MVP
-- traffic In/Out chart, the API/UI can treat transit/unknown as outbound until
-- local networks are configured.

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
    minute,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM
(
    SELECT
        minute,
        multiIf(
            src_is_local AND dst_is_local, 'internal',
            src_is_local AND NOT dst_is_local, 'out',
            NOT src_is_local AND dst_is_local, 'in',
            'transit'
        ) AS direction,
        bytes,
        packets
    FROM
    (
        SELECT
            toStartOfMinute(time_received_ns) AS minute,
            multiIf(
                etype = 0x0800, dictHas('default.local_networks_dict', tuple(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))))),
                etype = 0x86DD, dictHas('default.local_networks_dict', tuple(reinterpretAsIPv6(src_addr))),
                0
            ) AS src_is_local,
            multiIf(
                etype = 0x0800, dictHas('default.local_networks_dict', tuple(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))),
                etype = 0x86DD, dictHas('default.local_networks_dict', tuple(reinterpretAsIPv6(dst_addr))),
                0
            ) AS dst_is_local,
            bytes,
            packets
        FROM default.flows_raw
    )
)
GROUP BY
    minute,
    direction;

-- Backfill template for historical data already present before the MV was
-- created. Run by small windows, not for months at once.
--
-- INSERT INTO default.traffic_1m
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
--         WHERE time_received_ns >= toDateTime64('2026-05-14 00:00:00', 9, 'UTC')
--           AND time_received_ns <  toDateTime64('2026-05-14 01:00:00', 9, 'UTC')
--     )
-- )
-- GROUP BY
--     minute,
--     direction;
