-- Switch service rollup materialized views to range-aware port dictionary
-- without dropping already accumulated aggregate tables.
--
-- Run after migrate_port_services_ranges.sh.
--
-- Existing rows in traffic_service_1m / traffic_unknown_port_1m are preserved.
-- Only new flows will use port ranges. Rebuild/backfill selected periods
-- separately if historical service classification must change too.

DROP TABLE IF EXISTS default.traffic_service_1m_mv;

CREATE MATERIALIZED VIEW default.traffic_service_1m_mv
TO default.traffic_service_1m
AS
WITH
    multiIf(
        f.proto = 6, 'tcp',
        f.proto = 17, 'udp',
        f.proto = 1, 'icmp',
        f.proto = 58, 'icmpv6',
        f.proto = 132, 'sctp',
        'other'
    ) AS transport,
    dst_svc.service_code != '' AS has_dst_service,
    src_svc.service_code != '' AS has_src_service,
    multiIf(has_dst_service, 'dst', has_src_service, 'src', 'unknown') AS service_side,
    multiIf(has_dst_service, toUInt16(f.dst_port), has_src_service, toUInt16(f.src_port), toUInt16(0)) AS service_port,
    multiIf(has_dst_service, dst_svc.service_code, has_src_service, src_svc.service_code, 'unknown') AS service_code,
    multiIf(has_dst_service, dst_svc.service_name, has_src_service, src_svc.service_name, 'Unknown') AS service_name,
    multiIf(has_dst_service, dst_svc.category, has_src_service, src_svc.category, 'unknown') AS category
SELECT
    toStartOfMinute(f.time_received_ns) AS minute,
    f.source_id,
    f.direction,
    f.proto,
    transport,
    service_side,
    service_port,
    service_code,
    service_name,
    category,
    sum(f.bytes) AS bytes,
    sum(f.packets) AS packets,
    count() AS flows_count
FROM default.flows_raw AS f
LEFT JOIN default.port_services_expanded_enabled AS dst_svc
    ON dst_svc.transport = transport
   AND dst_svc.port = toUInt16(f.dst_port)
LEFT JOIN default.port_services_expanded_enabled AS src_svc
    ON src_svc.transport = transport
   AND src_svc.port = toUInt16(f.src_port)
GROUP BY
    minute,
    f.source_id,
    f.direction,
    f.proto,
    transport,
    service_side,
    service_port,
    service_code,
    service_name,
    category;

DROP TABLE IF EXISTS default.traffic_unknown_port_1m_mv;

CREATE MATERIALIZED VIEW default.traffic_unknown_port_1m_mv
TO default.traffic_unknown_port_1m
AS
SELECT
    toStartOfMinute(f.time_received_ns) AS minute,
    f.source_id,
    f.direction,
    f.proto,
    multiIf(
        f.proto = 6, 'tcp',
        f.proto = 17, 'udp',
        f.proto = 1, 'icmp',
        f.proto = 58, 'icmpv6',
        f.proto = 132, 'sctp',
        'other'
    ) AS transport,
    multiIf(f.dst_port > 0, 'dst', f.src_port > 0, 'src', 'unknown') AS port_side,
    multiIf(f.dst_port > 0, toUInt16(f.dst_port), f.src_port > 0, toUInt16(f.src_port), toUInt16(0)) AS port,
    sum(f.bytes) AS bytes,
    sum(f.packets) AS packets,
    count() AS flows_count
FROM default.flows_raw AS f
LEFT JOIN default.port_services_expanded_enabled AS dst_svc
    ON dst_svc.transport = multiIf(
        f.proto = 6, 'tcp',
        f.proto = 17, 'udp',
        f.proto = 1, 'icmp',
        f.proto = 58, 'icmpv6',
        f.proto = 132, 'sctp',
        'other'
    )
   AND dst_svc.port = toUInt16(f.dst_port)
LEFT JOIN default.port_services_expanded_enabled AS src_svc
    ON src_svc.transport = multiIf(
        f.proto = 6, 'tcp',
        f.proto = 17, 'udp',
        f.proto = 1, 'icmp',
        f.proto = 58, 'icmpv6',
        f.proto = 132, 'sctp',
        'other'
    )
   AND src_svc.port = toUInt16(f.src_port)
WHERE
    dst_svc.service_code = ''
    AND src_svc.service_code = ''
GROUP BY
    minute,
    f.source_id,
    f.direction,
    f.proto,
    transport,
    port_side,
    port;
