-- Minute-level traffic by country for heatmaps and top-country tables.
--
-- Each flow contributes four logical rows:
--   ip + src, ip + dst, asn + src, asn + dst
--
-- IP country uses default.geo_country_dict (prefix allocation country).
-- ASN country uses default.asn_registry_enriched.cc (registry country).
-- Empty or missing lookups are stored as ??.
--
-- Production ingest: NO sync Materialized View. Table is filled by async rollup
-- job traffic_country_1m (scripts/traffic_rollup_async.py). SELECT body:
-- scripts/traffic_rollup_jobs.py

DROP TABLE IF EXISTS default.traffic_country_1m_mv;

CREATE TABLE IF NOT EXISTS default.traffic_country_1m
(
    minute        DateTime('UTC'),
    source_id     LowCardinality(String),
    country_basis LowCardinality(String), -- ip / asn
    country_side  LowCardinality(String), -- src / dst
    direction     LowCardinality(String),
    country_code  LowCardinality(String),
    bytes         UInt64,
    packets       UInt64,
    flows_count   UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, source_id, country_basis, country_side, direction, country_code)
SETTINGS index_granularity = 8192;
