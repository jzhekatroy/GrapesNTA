-- Minute-level traffic by uplink/IX label.
--
-- For out traffic the remote side is dst_label; for in traffic it is src_label.
-- Transit is grouped by both side labels when available.

CREATE TABLE IF NOT EXISTS default.traffic_uplink_1m
(
    minute      DateTime('UTC'),
    direction   LowCardinality(String),
    uplink      LowCardinality(String),
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, direction, uplink)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS default.traffic_uplink_1m_mv
TO default.traffic_uplink_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    direction,
    multiIf(
        direction = 'out', dst_label,
        direction = 'in', src_label,
        src_label != '', src_label,
        dst_label
    ) AS uplink,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM default.flows_raw
WHERE direction IN ('in', 'out', 'transit')
  AND (src_label != '' OR dst_label != '')
GROUP BY
    minute,
    direction,
    uplink;
