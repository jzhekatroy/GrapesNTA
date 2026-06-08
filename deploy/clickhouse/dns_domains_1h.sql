-- DNS top domains rollup for long UI periods.
-- One row per hour/source/domain/qtype.

DROP TABLE IF EXISTS default.dns_domains_1h_mv;

CREATE TABLE IF NOT EXISTS default.dns_domains_1h
(
    hour        DateTime('UTC'),
    source_id   LowCardinality(String),
    query_name  String,
    qtype       LowCardinality(String),

    queries     UInt64,
    responses   UInt64,
    nxdomain    UInt64,
    servfail    UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, source_id, query_name, qtype)
TTL hour + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW default.dns_domains_1h_mv
TO default.dns_domains_1h
AS
SELECT
    toStartOfHour(toDateTime(ts)) AS hour,
    source_id,
    query_name,
    qtype,
    countIf(is_response = 0) AS queries,
    countIf(is_response = 1) AS responses,
    countIf(is_response = 1 AND rcode = 3) AS nxdomain,
    countIf(is_response = 1 AND rcode = 2) AS servfail
FROM default.dns_log
GROUP BY
    hour,
    source_id,
    query_name,
    qtype;
