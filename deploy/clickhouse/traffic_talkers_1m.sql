-- Minute-level top-talkers aggregates for UI tables.
--
-- traffic_talker_1m:
--   one logical row per endpoint side (src and dst) per raw flow.
--   UI tabs:
--     Sources      -> endpoint_side = 'src'
--     Destinations -> endpoint_side = 'dst'
--
-- traffic_pair_1m:
--   one row per src -> dst pair per minute.
--   UI tab:
--     Pairs -> src endpoint + dst endpoint
--
-- Production ingest: NO sync Materialized Views. Tables are filled by async
-- rollups traffic_talker_1m / traffic_pair_1m (scripts/traffic_rollup_async.py).
-- SELECT bodies: scripts/traffic_rollup_jobs.py

DROP TABLE IF EXISTS default.traffic_talker_1m_mv;
DROP TABLE IF EXISTS default.traffic_pair_1m_mv;

CREATE TABLE IF NOT EXISTS default.traffic_talker_1m
(
    minute                DateTime('UTC'),
    source_id             LowCardinality(String),
    endpoint_side         LowCardinality(String), -- src / dst
    direction             LowCardinality(String),
    endpoint_ip           String,
    endpoint_asn          UInt32,
    endpoint_as_name      String,
    endpoint_ip_country   LowCardinality(String),
    endpoint_as_country   LowCardinality(String),
    endpoint_scope        LowCardinality(String),
    endpoint_label        String,
    endpoint_network_name String,
    endpoint_network_role LowCardinality(String),
    bytes                 UInt64,
    packets               UInt64,
    flows_count           UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (
    minute,
    source_id,
    endpoint_side,
    direction,
    endpoint_ip,
    endpoint_asn,
    endpoint_ip_country,
    endpoint_as_country,
    endpoint_scope,
    endpoint_network_role
)
TTL minute + INTERVAL 2 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.traffic_pair_1m
(
    minute          DateTime('UTC'),
    source_id       LowCardinality(String),
    direction       LowCardinality(String),
    src_ip          String,
    dst_ip          String,
    src_asn         UInt32,
    dst_asn         UInt32,
    src_as_name     String,
    dst_as_name     String,
    src_ip_country  LowCardinality(String),
    dst_ip_country  LowCardinality(String),
    src_as_country  LowCardinality(String),
    dst_as_country  LowCardinality(String),
    src_scope       LowCardinality(String),
    dst_scope       LowCardinality(String),
    src_label       String,
    dst_label       String,
    bytes           UInt64,
    packets         UInt64,
    flows_count     UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (
    minute,
    source_id,
    direction,
    src_ip,
    dst_ip,
    src_asn,
    dst_asn,
    src_ip_country,
    dst_ip_country
)
TTL minute + INTERVAL 2 DAY
SETTINGS index_granularity = 8192;
