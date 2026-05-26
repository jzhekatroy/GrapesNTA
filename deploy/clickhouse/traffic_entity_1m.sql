-- Minute-level traffic by entity and direction.
--
-- Uses src_entity for out/internal; dst_entity for in when src_entity is empty.

CREATE TABLE IF NOT EXISTS default.traffic_entity_1m
(
    minute      DateTime('UTC'),
    direction   LowCardinality(String),
    entity_id   LowCardinality(String),
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, direction, entity_id)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_entity_1m_mv;

CREATE MATERIALIZED VIEW default.traffic_entity_1m_mv
TO default.traffic_entity_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    direction,
    multiIf(
        direction = 'out', src_entity,
        direction = 'in', dst_entity,
        src_entity != '', src_entity,
        dst_entity
    ) AS entity_id,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM default.flows_raw
WHERE direction IN ('in', 'out', 'internal')
  AND (src_entity != '' OR dst_entity != '')
GROUP BY
    minute,
    direction,
    entity_id;
