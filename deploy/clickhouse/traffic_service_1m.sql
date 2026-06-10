-- Minute-level traffic by application/service inferred from transport + port.
--
-- This complements traffic_protocol_1m:
--   traffic_protocol_1m = raw IP protocol numbers (TCP/UDP/GRE/ESP/...)
--   traffic_service_1m  = known services from port_services (HTTPS/NTP/DNS/...)
--
-- Port ranges are supported through default.port_services_expanded_enabled:
-- UI stores one rule as port_from/port_to, while this MV joins by exact port
-- to keep ingestion cheap.

DROP TABLE IF EXISTS default.traffic_service_1m_mv;
DROP TABLE IF EXISTS default.traffic_service_1m;

CREATE TABLE default.traffic_service_1m
(
    minute        DateTime('UTC'),
    source_id     LowCardinality(String),
    direction     LowCardinality(String),
    proto         UInt32,
    transport     LowCardinality(String),
    service_side  LowCardinality(String), -- dst / src / unknown
    service_port  UInt16,
    service_code  LowCardinality(String),
    service_name  String,
    category      LowCardinality(String),
    bytes         UInt64,
    packets       UInt64,
    flows_count   UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, direction, transport, category, service_code, service_name, service_port, service_side, proto)
SETTINGS index_granularity = 8192;

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
