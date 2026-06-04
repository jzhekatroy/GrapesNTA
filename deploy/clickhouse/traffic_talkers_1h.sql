-- Hour-level top-talkers rollups for UI tables over multi-hour periods.
--
-- Source tables:
--   traffic_talker_1m -> traffic_talker_1h
--   traffic_pair_1m   -> traffic_pair_1h
--
-- UI guidance:
--   up to 1h     -> traffic_talker_1m / traffic_pair_1m
--   3h and more -> traffic_talker_1h / traffic_pair_1h

DROP TABLE IF EXISTS default.traffic_talker_1h_mv;
DROP TABLE IF EXISTS default.traffic_pair_1h_mv;
DROP TABLE IF EXISTS default.traffic_talker_1h;
DROP TABLE IF EXISTS default.traffic_pair_1h;

CREATE TABLE default.traffic_talker_1h
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

CREATE MATERIALIZED VIEW default.traffic_talker_1h_mv
TO default.traffic_talker_1h
AS
SELECT
    toStartOfHour(minute) AS hour,
    source_id,
    endpoint_side,
    direction,
    endpoint_ip,
    endpoint_asn,
    endpoint_as_name,
    endpoint_ip_country,
    endpoint_as_country,
    endpoint_scope,
    endpoint_label,
    endpoint_network_name,
    endpoint_network_role,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flows_count) AS flows_count
FROM default.traffic_talker_1m
GROUP BY
    hour,
    source_id,
    endpoint_side,
    direction,
    endpoint_ip,
    endpoint_asn,
    endpoint_as_name,
    endpoint_ip_country,
    endpoint_as_country,
    endpoint_scope,
    endpoint_label,
    endpoint_network_name,
    endpoint_network_role;

CREATE TABLE default.traffic_pair_1h
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

CREATE MATERIALIZED VIEW default.traffic_pair_1h_mv
TO default.traffic_pair_1h
AS
SELECT
    toStartOfHour(minute) AS hour,
    source_id,
    direction,
    src_ip,
    dst_ip,
    src_asn,
    dst_asn,
    src_as_name,
    dst_as_name,
    src_ip_country,
    dst_ip_country,
    src_as_country,
    dst_as_country,
    src_scope,
    dst_scope,
    src_label,
    dst_label,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    sum(flows_count) AS flows_count
FROM default.traffic_pair_1m
GROUP BY
    hour,
    source_id,
    direction,
    src_ip,
    dst_ip,
    src_asn,
    dst_asn,
    src_as_name,
    dst_as_name,
    src_ip_country,
    dst_ip_country,
    src_as_country,
    dst_as_country,
    src_scope,
    dst_scope,
    src_label,
    dst_label;
