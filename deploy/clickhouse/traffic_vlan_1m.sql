-- Minute-level traffic by VLAN attachment type and direction.
--
-- Uses src side attachment for out/internal; dst side for in.
--
-- Production ingest: NO sync Materialized View. Table is filled by async rollup
-- job traffic_vlan_1m (scripts/traffic_rollup_async.py). SELECT body:
-- scripts/traffic_rollup_jobs.py

CREATE TABLE IF NOT EXISTS default.traffic_vlan_1m
(
    minute           DateTime('UTC'),
    source_id        LowCardinality(String),
    direction        LowCardinality(String),
    attachment_type  LowCardinality(String),
    vlan_id          UInt16,
    bytes            UInt64,
    packets          UInt64,
    flows_count      UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, direction, attachment_type, vlan_id)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.traffic_vlan_1m_mv;
