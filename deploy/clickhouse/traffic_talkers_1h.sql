-- Hour-level top-talkers rollups for UI tables over multi-hour periods.
--
-- Source tables:
--   traffic_talker_1m -> traffic_talker_1h
--   traffic_pair_1m   -> traffic_pair_1h
--
-- UI guidance:
--   up to 1h     -> traffic_talker_1m / traffic_pair_1m
--   3h and more -> traffic_talker_1h / traffic_pair_1h
--
-- Production ingest: NO sync Materialized Views. Tables are filled by async
-- rollups traffic_talker_1h / traffic_pair_1h (scripts/traffic_rollup_async.py).
-- SELECT bodies: scripts/traffic_rollup_jobs.py

DROP TABLE IF EXISTS default.traffic_talker_1h_mv;
DROP TABLE IF EXISTS default.traffic_pair_1h_mv;

CREATE TABLE IF NOT EXISTS default.traffic_talker_1h
(
    hour                  DateTime('UTC'),
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
PARTITION BY toYYYYMMDD(hour)
ORDER BY (
    hour,
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
TTL hour + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.traffic_pair_1h
(
    hour            DateTime('UTC'),
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
PARTITION BY toYYYYMMDD(hour)
ORDER BY (
    hour,
    source_id,
    direction,
    src_ip,
    dst_ip,
    src_asn,
    dst_asn,
    src_ip_country,
    dst_ip_country
)
TTL hour + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
