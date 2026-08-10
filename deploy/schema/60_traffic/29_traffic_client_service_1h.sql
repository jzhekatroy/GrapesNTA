-- Cabinet showcase: client traffic by application service (hourly).
--
-- A port the service dictionary does not know is NOT collapsed into 'other' on
-- its own: measured on a real client, 78% of outbound bytes sat on one stable
-- port (12545/tcp) that the dictionary only covers for udp, so the cabinet
-- would have answered "which services do you use" with "Other, 78%". Instead
-- such traffic gets service_code='port' and keeps the port in service_port, so
-- the client at least sees "tcp/12545" and recognises it.
--
-- Only genuinely unidentifiable traffic still collapses to 'other': that means
-- both ports are ephemeral (>= 32768), or there are no ports at all as with
-- ICMP. Keeping ephemeral ports would let a port scan invent thousands of rows
-- per client-hour.
--
-- service_port and port_owner are meaningful only when service_code='port';
-- named services and 'other' carry 0 and ''. port_owner says whose port was
-- kept, seen from the client: 'local' is a port the client itself listens on,
-- 'remote' is a port it talked to. Without it "tcp/12545" would not tell the
-- client whether it serves that port or uses it.
CREATE TABLE IF NOT EXISTS default.traffic_client_service_1h
(
    `hour` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `transport` LowCardinality(String),
    `service_code` LowCardinality(String),
    `service_name` String,
    `category` LowCardinality(String),
    `service_port` UInt16,
    `port_owner` LowCardinality(String),
    `bytes` UInt64,
    `packets` UInt64,
    `flows_count` UInt64,
    INDEX idx_hour hour TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(hour)
ORDER BY (client_id, hour, source_id, direction, transport, category, service_code, service_name, service_port, port_owner)
TTL hour + toIntervalDay(180)
SETTINGS index_granularity = 8192;
