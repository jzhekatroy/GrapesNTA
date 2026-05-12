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
