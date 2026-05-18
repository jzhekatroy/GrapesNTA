-- DEPRECATED: minute-level IPv4 traffic aggregate by source/destination ASN.
--
-- Kept for backward compatibility with the first MVP dashboard query. The
-- current path is:
--
--   xdpflowd classifier -> flows_raw.direction/src_asn/dst_asn
--      -> traffic_direction_1m / traffic_uplink_1m / traffic_customer_1m
--
-- This older aggregate avoided scanning default.flows_raw on every dashboard
-- request:
--
--   flows_raw -> bgp_origin_asn_dict -> traffic_asn_pair_1m
--
-- The table intentionally stores src_asn/dst_asn, not direction. Direction is
-- computed at read time from default.local_asns_enabled, so changing the list
-- of local/customer ASNs does not require rebuilding historical aggregates.
--
-- IPv6 is not included in this MVP aggregate. For operators without ASNs or
-- IPv6-heavy deployments, use the future prefix-based direction path:
-- local_networks_dict in ClickHouse or a prefix trie in the flow collector.
--
-- Compatible with old clickhouse-client 18.x --multiquery. Keep this file free
-- from column CODEC/TTL syntax that the old client parser does not understand.

CREATE TABLE IF NOT EXISTS default.traffic_asn_pair_1m
(
    minute      DateTime('UTC'),
    src_asn     UInt32,
    dst_asn     UInt32,
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, src_asn, dst_asn)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS default.traffic_asn_pair_1m_mv
TO default.traffic_asn_pair_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    dictGetUInt32(
        'default.bgp_origin_asn_dict',
        'origin_asn',
        tuple(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))))
    ) AS src_asn,
    dictGetUInt32(
        'default.bgp_origin_asn_dict',
        'origin_asn',
        tuple(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))
    ) AS dst_asn,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM default.flows_raw
WHERE etype = 0x0800
GROUP BY
    minute,
    src_asn,
    dst_asn;

-- Backfill template for selected history. Run in small windows.
--
-- INSERT INTO default.traffic_asn_pair_1m
-- SELECT
--     toStartOfMinute(time_received_ns) AS minute,
--     dictGetUInt32(
--         'default.bgp_origin_asn_dict',
--         'origin_asn',
--         tuple(toIPv4(reinterpretAsUInt32(reverse(substring(src_addr, 1, 4)))))
--     ) AS src_asn,
--     dictGetUInt32(
--         'default.bgp_origin_asn_dict',
--         'origin_asn',
--         tuple(toIPv4(reinterpretAsUInt32(reverse(substring(dst_addr, 1, 4)))))
--     ) AS dst_asn,
--     sum(bytes) AS bytes,
--     sum(packets) AS packets,
--     count() AS flows_count
-- FROM default.flows_raw
-- WHERE etype = 0x0800
--   AND time_received_ns >= toDateTime64('2026-05-15 10:00:00', 9, 'UTC')
--   AND time_received_ns <  toDateTime64('2026-05-15 11:00:00', 9, 'UTC')
-- GROUP BY
--     minute,
--     src_asn,
--     dst_asn
-- SETTINGS
--     max_memory_usage = 4000000000,
--     max_bytes_before_external_group_by = 2000000000,
--     max_threads = 4;
