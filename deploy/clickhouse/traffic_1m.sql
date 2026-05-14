-- Minute-level traffic aggregate for dashboard charts.
--
-- Apply after default.flows_raw exists. This MVP version does not require
-- local_networks yet: all rows are written with direction='unknown'. After the
-- local network dictionary is introduced, replace the MV direction expression
-- and rebuild the selected history from flows_raw.

CREATE TABLE IF NOT EXISTS default.traffic_1m
(
    minute      DateTime('UTC') CODEC(Delta, ZSTD(1)),
    direction   LowCardinality(String), -- in / out / internal / transit / unknown
    bytes       UInt64,
    packets     UInt64,
    flows_count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, direction)
TTL minute + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS default.traffic_1m_mv
TO default.traffic_1m
AS
SELECT
    toStartOfMinute(time_received_ns) AS minute,
    'unknown' AS direction,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows_count
FROM default.flows_raw
GROUP BY
    minute,
    direction;

-- Backfill template for historical data already present before the MV was
-- created. Run by small windows, not for months at once.
--
-- INSERT INTO default.traffic_1m
-- SELECT
--     toStartOfMinute(time_received_ns) AS minute,
--     'unknown' AS direction,
--     sum(bytes) AS bytes,
--     sum(packets) AS packets,
--     count() AS flows_count
-- FROM default.flows_raw
-- WHERE time_received_ns >= toDateTime64('2026-05-14 00:00:00', 9, 'UTC')
--   AND time_received_ns <  toDateTime64('2026-05-14 01:00:00', 9, 'UTC')
-- GROUP BY
--     minute,
--     direction;
