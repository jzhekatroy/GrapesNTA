-- Hour-level ASN top-talkers rollups for UI tables over multi-hour periods.
--
-- Source tables:
--   traffic_asn_1m       -> traffic_asn_1h
--   traffic_asn_pair_1m  -> traffic_asn_pair_1h
--
-- UI guidance (after UI migration):
--   up to 1h     -> traffic_asn_1m / traffic_asn_pair_1m
--   3h and more -> traffic_asn_1h / traffic_asn_pair_1h
--
-- Production ingest: NO sync Materialized Views. Tables are filled by async
-- rollups traffic_asn_1h / traffic_asn_pair_1h (scripts/traffic_rollup_async.py).
-- SELECT bodies: scripts/traffic_rollup_jobs.py

DROP TABLE IF EXISTS default.traffic_asn_1h_mv;
DROP TABLE IF EXISTS default.traffic_asn_pair_1h_mv;

CREATE TABLE IF NOT EXISTS default.traffic_asn_1h
(
    hour                DateTime('UTC'),
    source_id           LowCardinality(String),
    endpoint_side       LowCardinality(String), -- src / dst
    direction           LowCardinality(String),
    endpoint_asn        UInt32,
    endpoint_as_name    String,
    endpoint_as_country LowCardinality(String),
    bytes               UInt64,
    packets             UInt64,
    flows_count         UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(hour)
ORDER BY (
    hour,
    source_id,
    endpoint_side,
    direction,
    endpoint_asn
)
TTL hour + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.traffic_asn_pair_1h
(
    hour           DateTime('UTC'),
    source_id      LowCardinality(String),
    direction      LowCardinality(String),
    src_asn        UInt32,
    dst_asn        UInt32,
    src_as_name    String,
    dst_as_name    String,
    src_as_country LowCardinality(String),
    dst_as_country LowCardinality(String),
    bytes          UInt64,
    packets        UInt64,
    flows_count    UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(hour)
ORDER BY (
    hour,
    source_id,
    direction,
    src_asn,
    dst_asn
)
TTL hour + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
