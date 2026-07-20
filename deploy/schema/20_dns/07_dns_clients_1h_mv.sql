CREATE MATERIALIZED VIEW IF NOT EXISTS default.dns_clients_1h_mv TO default.dns_clients_1h
(
    `hour` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `client_ip` FixedString(16),
    `queries` UInt64,
    `responses` UInt64,
    `nxdomain` UInt64,
    `servfail` UInt64,
    `unique_domains_state` AggregateFunction(uniqCombined, String)
)
AS SELECT
    toStartOfHour(toDateTime(ts)) AS hour,
    source_id,
    client_ip,
    countIf(is_response = 0) AS queries,
    countIf(is_response = 1) AS responses,
    countIf((is_response = 1) AND (rcode = 3)) AS nxdomain,
    countIf((is_response = 1) AND (rcode = 2)) AS servfail,
    uniqCombinedStateIf(query_name, is_response = 0) AS unique_domains_state
FROM default.dns_log
GROUP BY
    hour,
    source_id,
    client_ip;
