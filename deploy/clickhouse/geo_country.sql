-- Country-only IP prefixes from RIR delegated-extended statistics.
-- Apply once for tables, then run scripts/load_rir_geo.py for daily refresh.
-- The loader creates/updates geo_country_dict because its SOURCE credentials
-- can differ from the client credentials used to load data.

CREATE TABLE IF NOT EXISTS default.geo_prefix_country_staging
(
    prefix      String,
    family      UInt8,
    cc          FixedString(2),
    rir         LowCardinality(String),
    status      LowCardinality(String),
    alloc_date  Date,
    source      LowCardinality(String),
    snapshot_ts DateTime
)
ENGINE = MergeTree
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.geo_prefix_country
(
    prefix      String,
    family      UInt8,
    cc          FixedString(2),
    rir         LowCardinality(String),
    status      LowCardinality(String),
    alloc_date  Date,
    source      LowCardinality(String),
    snapshot_ts DateTime
)
ENGINE = MergeTree
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;

-- geo_country_dict is created by scripts/load_rir_geo.py using
-- GEOLOADERD_DICT_SOURCE_* so dictionary reads can use the ClickHouse server's
-- internal address (for example 127.0.0.1:9000) while the loader uses an
-- external address (for example 95.215.1.30:6124).

-- ASN allocation registry from the same RIR delegated-extended statistics.
-- This maps origin_asn -> country/RIR/status/date. RIR delegated files do not
-- include organization names, so names live in a separate editable/enrichment
-- table (asn_names) and are not overwritten by daily RIR refreshes.
CREATE TABLE IF NOT EXISTS default.asn_registry_staging
(
    asn         UInt32,
    cc          FixedString(2),
    rir         LowCardinality(String),
    status      LowCardinality(String),
    alloc_date  Date,
    source      LowCardinality(String),
    snapshot_ts DateTime
)
ENGINE = MergeTree
ORDER BY asn
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.asn_registry
(
    asn         UInt32,
    cc          FixedString(2),
    rir         LowCardinality(String),
    status      LowCardinality(String),
    alloc_date  Date,
    source      LowCardinality(String),
    snapshot_ts DateTime
)
ENGINE = MergeTree
ORDER BY asn
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.asn_names
(
    asn        UInt32,
    name       String,
    org_id     String DEFAULT '',
    source     LowCardinality(String) DEFAULT 'manual',
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY asn
SETTINGS index_granularity = 8192;

CREATE VIEW IF NOT EXISTS default.asn_registry_enriched AS
SELECT
    r.asn,
    if(ifNull(n.name, '') = '', concat('AS', toString(r.asn)), n.name) AS name,
    r.cc,
    r.rir,
    r.status,
    r.alloc_date,
    r.source,
    r.snapshot_ts
FROM default.asn_registry AS r
LEFT JOIN
(
    SELECT
        asn,
        argMax(name, updated_at) AS name
    FROM default.asn_names
    GROUP BY asn
) AS n ON r.asn = n.asn;
