-- Minute-level ASN top-talkers aggregates for UI tables.
--
-- traffic_asn_1m:
--   one logical row per endpoint side (src and dst) per raw flow, grouped by ASN.
--   UI tabs (after UI migration):
--     Sources      -> endpoint_side = 'src'
--     Destinations -> endpoint_side = 'dst'
--
-- traffic_asn_pair_1m:
--   one row per src_asn -> dst_asn pair per minute.
--   UI tab:
--     Pairs -> src_asn + dst_asn
--
-- Production ingest: NO sync Materialized Views. Tables are filled by async
-- rollups traffic_asn_1m / traffic_asn_pair_1m (scripts/traffic_rollup_async.py).
-- SELECT bodies: scripts/traffic_rollup_jobs.py

DROP TABLE IF EXISTS default.traffic_asn_1m_mv;
DROP TABLE IF EXISTS default.traffic_asn_pair_1m_mv;

CREATE TABLE IF NOT EXISTS default.traffic_asn_1m
(
    minute              DateTime('UTC'),
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
PARTITION BY toYYYYMMDD(minute)
ORDER BY (
    minute,
    source_id,
    endpoint_side,
    direction,
    endpoint_asn
)
TTL minute + INTERVAL 2 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.traffic_asn_pair_1m
(
    minute         DateTime('UTC'),
    source_id      LowCardinality(String),
    direction      LowCardinality(String),
    src_asn        UInt32,
    dst_asn        UInt32,
    src_as_name    String,
    dst_as_name    String,
    src_as_country LowCardinality(String),
    dst_as_country LowCardinality(String),
    bytes          UInt64,
    packets         UInt64,
    flows_count    UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (
    minute,
    source_id,
    direction,
    src_asn,
    dst_asn
)
TTL minute + INTERVAL 2 DAY
SETTINGS index_granularity = 8192;
