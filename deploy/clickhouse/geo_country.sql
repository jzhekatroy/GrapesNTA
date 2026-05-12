-- Country-only IP prefixes from RIR delegated-extended statistics.
-- Apply once, then run scripts/load_rir_geo.py (see docs/geoip_country.md) for daily refresh.

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

-- Longest-prefix match lookup. Key column must be CIDR strings (e.g. 192.0.2.0/24, 2001:db8::/32).
-- After loading data into geo_prefix_country, run: SYSTEM RELOAD DICTIONARY default.geo_country_dict;
CREATE DICTIONARY IF NOT EXISTS default.geo_country_dict
(
    prefix      String,
    cc          String,
    rir         String,
    source      String,
    snapshot_ts DateTime
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(TABLE 'geo_prefix_country'))
LAYOUT(IP_TRIE)
LIFETIME(0);
