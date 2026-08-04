-- DNS top servers rollup for long UI periods.
--
-- Apply on an existing installation:
--   clickhouse-client ... --multiquery < deploy/clickhouse/dns_servers_1h.sql
--
-- dns_clients_1h and dns_domains_1h carry no server_ip, so "which servers is
-- this client hammering" was only answerable from raw dns_log — that is, for
-- the last 30 minutes. This rollup makes the question answerable over the same
-- periods as the other two tops.
--
-- client_ip / server_ip are roles rather than src/dst, so a single server row
-- covers both the queries sent to it and the responses it returned.

DROP TABLE IF EXISTS default.dns_servers_1h_mv;

CREATE TABLE IF NOT EXISTS default.dns_servers_1h
(
    hour      DateTime('UTC'),
    source_id LowCardinality(String),
    server_ip FixedString(16),

    queries   UInt64,
    responses UInt64,
    nxdomain  UInt64,
    servfail  UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, source_id, server_ip)
TTL hour + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW default.dns_servers_1h_mv
TO default.dns_servers_1h
AS
SELECT
    toStartOfHour(toDateTime(ts)) AS hour,
    source_id,
    server_ip,
    countIf(is_response = 0) AS queries,
    countIf(is_response = 1) AS responses,
    countIf(is_response = 1 AND rcode = 3) AS nxdomain,
    countIf(is_response = 1 AND rcode = 2) AS servfail
FROM default.dns_log
GROUP BY
    hour,
    source_id,
    server_ip;

-- Backfill the retention window from raw dns_log (the MV only sees new rows).
-- dns_log keeps 30 days, the rollup keeps 90; older hours simply stay empty.
INSERT INTO default.dns_servers_1h
SELECT
    toStartOfHour(toDateTime(ts)) AS hour,
    source_id,
    server_ip,
    countIf(is_response = 0) AS queries,
    countIf(is_response = 1) AS responses,
    countIf(is_response = 1 AND rcode = 3) AS nxdomain,
    countIf(is_response = 1 AND rcode = 2) AS servfail
FROM default.dns_log
WHERE ts < toStartOfHour(now())
GROUP BY
    hour,
    source_id,
    server_ip;
