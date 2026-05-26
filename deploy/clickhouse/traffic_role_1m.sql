-- Minute-level traffic by L3 role and direction.
--
-- Uses src_role for out/internal; dst_role for in when src_role is empty.

CREATE TABLE IF NOT EXISTS default.traffic_role_1m
(
    minute      DateTime('UTC'),
    direction   LowCardinality(String),
    role        LowCardinality(String),
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, direction, role)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_role_1m_mv;

CREATE MATERIALIZED VIEW default.traffic_role_1m_mv
TO default.traffic_role_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    direction,
    multiIf(
        direction = 'out', src_role,
        direction = 'in', dst_role,
        src_role != '', src_role,
        dst_role
    ) AS role,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM default.flows_raw
WHERE direction IN ('in', 'out', 'internal', 'transit', 'unknown')
  AND (src_role != '' OR dst_role != '')
GROUP BY
    minute,
    direction,
    role;
