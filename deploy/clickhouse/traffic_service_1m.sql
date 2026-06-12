-- Minute-level traffic by application/service inferred from transport + port.
--
-- This complements traffic_protocol_1m:
--   traffic_protocol_1m = raw IP protocol numbers (TCP/UDP/GRE/ESP/...)
--   traffic_service_1m  = known services from port_services (HTTPS/NTP/DNS/...)
--
-- Port ranges are supported through default.port_services_expanded_enabled.
--
-- Production ingest: NO sync Materialized View. Table is filled by async rollup
-- job traffic_service_1m (scripts/traffic_rollup_async.py). SELECT body:
-- scripts/traffic_rollup_jobs.py

DROP TABLE IF EXISTS default.traffic_service_1m_mv;

CREATE TABLE IF NOT EXISTS default.traffic_service_1m
(
    minute        DateTime('UTC'),
    source_id     LowCardinality(String),
    direction     LowCardinality(String),
    proto         UInt32,
    transport     LowCardinality(String),
    service_side  LowCardinality(String), -- dst / src / unknown
    service_port  UInt16,
    service_code  LowCardinality(String),
    service_name  String,
    category      LowCardinality(String),
    bytes         UInt64,
    packets       UInt64,
    flows_count   UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, direction, transport, category, service_code, service_name, service_port, service_side, proto)
SETTINGS index_granularity = 8192;
