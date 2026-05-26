-- Minute-level traffic by precomputed direction.
--
-- Source columns are written by xdpflowd classifier:
--   direction = in | out | internal | transit | unknown

CREATE TABLE IF NOT EXISTS default.traffic_direction_1m
(
    minute      DateTime('UTC'),
    direction   LowCardinality(String),
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, direction)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_direction_1m_mv;

CREATE MATERIALIZED VIEW default.traffic_direction_1m_mv
TO default.traffic_direction_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM default.flows_raw
GROUP BY
    minute,
    direction;
