-- Public IP prefix -> origin ASN fallback for traffic enrichment.
--
-- This table is intentionally separate from bgp_prefix_origin_current. BMP/BGP
-- remains the first remote ASN source; this snapshot is only a fallback when
-- the collector does not have a full-view table.
--
-- Filled by scripts/load_iptoasn_prefixes.py from https://iptoasn.com/.

CREATE TABLE IF NOT EXISTS default.ip_asn_prefixes_current
(
    prefix      String,
    family      UInt8,
    origin_asn  UInt32,
    cc          LowCardinality(String),
    as_name     String,
    source      LowCardinality(String),
    snapshot_ts DateTime('UTC')
)
ENGINE = MergeTree
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS default.ip_asn_prefixes_staging
(
    prefix      String,
    family      UInt8,
    origin_asn  UInt32,
    cc          LowCardinality(String),
    as_name     String,
    source      LowCardinality(String),
    snapshot_ts DateTime('UTC')
)
ENGINE = MergeTree
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;
