-- Minute-level traffic by IP protocol number and direction.
--
-- `proto` is the raw IP protocol number from flows_raw. The aggregate keeps
-- every observed protocol instead of limiting rows to TCP/UDP/ICMP.

CREATE TABLE IF NOT EXISTS default.traffic_protocol_1m
(
    minute      DateTime('UTC'),
    source_id   LowCardinality(String),
    proto       UInt32,
    direction   LowCardinality(String),
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, proto, direction)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_protocol_1m_mv;

CREATE MATERIALIZED VIEW default.traffic_protocol_1m_mv
TO default.traffic_protocol_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    source_id,
    proto,
    direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM default.flows_raw
GROUP BY
    minute,
    source_id,
    proto,
    direction;
