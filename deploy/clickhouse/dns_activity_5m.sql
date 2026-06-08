-- DNS activity rollup for long UI periods.
-- One row per 5-minute bucket/source/qtype/rcode.

DROP TABLE IF EXISTS default.dns_activity_5m_mv;

CREATE TABLE IF NOT EXISTS default.dns_activity_5m
(
    bucket      DateTime('UTC'),
    source_id   LowCardinality(String),
    qtype       LowCardinality(String),
    rcode       UInt8,

    queries     UInt64,
    responses   UInt64,
    nxdomain    UInt64,
    servfail    UInt64,
    raw_bytes   UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, source_id, qtype, rcode)
TTL bucket + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW default.dns_activity_5m_mv
TO default.dns_activity_5m
AS
SELECT
    toStartOfInterval(toDateTime(ts), INTERVAL 5 MINUTE) AS bucket,
    source_id,
    qtype,
    rcode,
    countIf(is_response = 0) AS queries,
    countIf(is_response = 1) AS responses,
    countIf(is_response = 1 AND rcode = 3) AS nxdomain,
    countIf(is_response = 1 AND rcode = 2) AS servfail,
    sum(toUInt64(raw_size)) AS raw_bytes
FROM default.dns_log
GROUP BY
    bucket,
    source_id,
    qtype,
    rcode;
