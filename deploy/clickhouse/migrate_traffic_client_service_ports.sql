-- Keep the port for services the dictionary does not know, and give every client
-- aggregate a retention.
--
-- Why: measured on a real client, 78% of outbound bytes sat on one stable port
-- (12545/tcp, which the dictionary only covers for udp), so the cabinet would
-- have answered "which services do you use" with "Other, 78%". Unclassified
-- traffic now carries service_code='port' plus the port itself and whose side it
-- is on, and only genuinely unidentifiable traffic stays 'other'.
--
-- The service tables are recreated rather than altered because the two new
-- columns join the sorting key, and the tables only hold a few hours of data so
-- far. Re-run the rollups afterwards - see the commands at the bottom.
--
-- Safe to re-run.

DROP TABLE IF EXISTS default.traffic_client_service_1h SYNC;

CREATE TABLE default.traffic_client_service_1h
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

DROP TABLE IF EXISTS default.traffic_client_service_1d SYNC;

CREATE TABLE default.traffic_client_service_1d
(
    `day` DateTime('UTC'),
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
    INDEX idx_day day TYPE minmax GRANULARITY 1
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (client_id, day, source_id, direction, transport, category, service_code, service_name, service_port, port_owner)
TTL day + toIntervalDay(730)
SETTINGS index_granularity = 8192;

-- Retention for the aggregates that were created without any: per-minute detail
-- lives two weeks (same as traffic_client_anomaly_1m, enough for a weekly
-- baseline), hourly half a year, daily two years. Without this they grow
-- forever, which is worst for the per-minute table.
ALTER TABLE default.traffic_client_1m         MODIFY TTL minute + toIntervalDay(14);
ALTER TABLE default.traffic_client_1h         MODIFY TTL hour + toIntervalDay(180);
ALTER TABLE default.traffic_client_1d         MODIFY TTL day + toIntervalDay(730);
ALTER TABLE default.traffic_client_country_1h MODIFY TTL hour + toIntervalDay(180);
ALTER TABLE default.traffic_client_country_1d MODIFY TTL day + toIntervalDay(730);
