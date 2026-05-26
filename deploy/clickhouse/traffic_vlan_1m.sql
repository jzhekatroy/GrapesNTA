-- Minute-level traffic by VLAN attachment type and direction.
--
-- Uses src side attachment for out/internal; dst side for in.

CREATE TABLE IF NOT EXISTS default.traffic_vlan_1m
(
    minute           DateTime('UTC'),
    direction        LowCardinality(String),
    attachment_type  LowCardinality(String),
    vlan_id          UInt16,
    bytes            UInt64,
    packets          UInt64,
    flows_count      UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, direction, attachment_type, vlan_id)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_vlan_1m_mv;

CREATE MATERIALIZED VIEW default.traffic_vlan_1m_mv
TO default.traffic_vlan_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    direction,
    multiIf(
        direction = 'out', src_attachment_kind,
        direction = 'in', dst_attachment_kind,
        src_attachment_kind != 'unknown', src_attachment_kind,
        dst_attachment_kind
    ) AS attachment_type,
    multiIf(
        direction = 'out', src_vlan,
        direction = 'in', dst_vlan,
        src_vlan != 0, src_vlan,
        dst_vlan
    ) AS vlan_id,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM default.flows_raw
WHERE direction IN ('in', 'out', 'internal', 'transit')
  AND (
      src_attachment_kind != 'unknown'
      OR dst_attachment_kind != 'unknown'
      OR src_vlan != 0
      OR dst_vlan != 0
  )
GROUP BY
    minute,
    direction,
    attachment_type,
    vlan_id;
