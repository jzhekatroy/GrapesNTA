-- DNS top clients rollup for long UI periods.
-- Uses AggregateFunction only for approximate unique-domain count.

DROP TABLE IF EXISTS default.dns_clients_1h_mv;

CREATE TABLE IF NOT EXISTS default.dns_clients_1h
(
    hour                 DateTime('UTC'),
    source_id            LowCardinality(String),
    client_ip            FixedString(16),

    queries              SimpleAggregateFunction(sum, UInt64),
    responses            SimpleAggregateFunction(sum, UInt64),
    nxdomain             SimpleAggregateFunction(sum, UInt64),
    servfail             SimpleAggregateFunction(sum, UInt64),
    unique_domains_state AggregateFunction(uniqCombined, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, source_id, client_ip)
TTL hour + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW default.dns_clients_1h_mv
TO default.dns_clients_1h
AS
SELECT
    toStartOfHour(toDateTime(ts)) AS hour,
    source_id,
    client_ip,
    countIf(is_response = 0) AS queries,
    countIf(is_response = 1) AS responses,
    countIf(is_response = 1 AND rcode = 3) AS nxdomain,
    countIf(is_response = 1 AND rcode = 2) AS servfail,
    uniqCombinedStateIf(query_name, is_response = 0) AS unique_domains_state
FROM default.dns_log
GROUP BY
    hour,
    source_id,
    client_ip;
