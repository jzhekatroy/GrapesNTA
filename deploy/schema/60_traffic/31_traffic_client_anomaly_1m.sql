-- Per-minute client profile for anomaly and DDoS detection.
--
-- Deliberately separate from the cabinet vitrines: an hour is too coarse for an
-- attack that unfolds in tens of seconds, while a full per-minute breakdown by
-- country would cost tens of millions of rows a day. Cardinality here is capped
-- by design - direction times transport is at most a dozen rows per client per
-- minute - so the table stays cheap while carrying the signals detection needs
-- and the plain vitrines lack.
--
-- direction is from the client's point of view, same as the other client tables.
--
-- syn_flows counts TCP flows that opened a connection (SYN set, ACK clear): a
-- SYN flood shows up as syn_flows growing while bytes barely move.
--
-- remote_ips_state answers "how many different peers", which is what separates a
-- distributed attack from an ordinary spike. It is an aggregate state rather
-- than a number because counts of distinct values cannot be summed across
-- minutes; use uniqCombinedMerge to read it. Same approach as dns_clients_1h.
--
-- TTL is 14 days, longer than the 2 days used by operator-wide per-minute
-- tables: detection compares against a daily and weekly baseline, and flows_raw
-- itself only keeps 6 days.
--
-- ORDER BY starts with client_id because every read is "one client over a
-- period". The bucket column is therefore not a primary key prefix, so the
-- rollup runner's idempotency probe and per-bucket DELETE need idx_minute.
CREATE TABLE IF NOT EXISTS default.traffic_client_anomaly_1m
(
    `minute` DateTime('UTC'),
    `client_id` LowCardinality(String),
    `source_id` LowCardinality(String),
    `direction` LowCardinality(String),
    `transport` LowCardinality(String),
    `bytes` SimpleAggregateFunction(sum, UInt64),
    `packets` SimpleAggregateFunction(sum, UInt64),
    `flows_count` SimpleAggregateFunction(sum, UInt64),
    `syn_flows` SimpleAggregateFunction(sum, UInt64),
    `remote_ips_state` AggregateFunction(uniqCombined, FixedString(16)),
    INDEX idx_minute minute TYPE minmax GRANULARITY 1
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (client_id, minute, source_id, direction, transport)
TTL minute + toIntervalDay(14)
SETTINGS index_granularity = 8192;
