-- Minute-level traffic by local customer/operator.
--
-- For out traffic the local side is src_operator; for in traffic it is
-- dst_operator. Internal traffic is grouped by src_operator when available.

CREATE TABLE IF NOT EXISTS default.traffic_customer_1m
(
    minute      DateTime('UTC'),
    direction   LowCardinality(String),
    operator_id LowCardinality(String),
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, direction, operator_id)
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS default.traffic_customer_1m_mv
TO default.traffic_customer_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    direction,
    multiIf(
        direction = 'out', src_operator,
        direction = 'in', dst_operator,
        src_operator != '', src_operator,
        dst_operator
    ) AS operator_id,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM default.flows_raw
WHERE direction IN ('in', 'out', 'internal')
  AND (src_operator != '' OR dst_operator != '')
GROUP BY
    minute,
    direction,
    operator_id;
