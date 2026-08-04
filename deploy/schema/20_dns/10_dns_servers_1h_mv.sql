CREATE MATERIALIZED VIEW IF NOT EXISTS default.dns_servers_1h_mv TO default.dns_servers_1h
(
    `hour` DateTime('UTC'),
    `source_id` LowCardinality(String),
    `server_ip` FixedString(16),
    `queries` UInt64,
    `responses` UInt64,
    `nxdomain` UInt64,
    `servfail` UInt64
)
AS SELECT
    toStartOfHour(toDateTime(ts)) AS hour,
    source_id,
    server_ip,
    countIf(is_response = 0) AS queries,
    countIf(is_response = 1) AS responses,
    countIf((is_response = 1) AND (rcode = 3)) AS nxdomain,
    countIf((is_response = 1) AND (rcode = 2)) AS servfail
FROM default.dns_log
GROUP BY
    hour,
    source_id,
    server_ip;
