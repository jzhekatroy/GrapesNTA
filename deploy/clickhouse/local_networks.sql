-- Local network prefixes used to classify traffic direction.
--
-- Apply once, then populate default.local_networks either manually (MoonShine)
-- or via scripts/load_local_networks_from_asn.py.
--
-- The IP_TRIE dictionary is created by scripts/load_local_networks_from_asn.py
-- because its SOURCE credentials are deployment-specific.

CREATE TABLE IF NOT EXISTS default.local_networks
(
    prefix     String,
    family     UInt8,
    name       String,
    source     LowCardinality(String),
    enabled    UInt8,
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (family, prefix)
SETTINGS index_granularity = 8192;

-- Keep the dictionary source free from FINAL. ReplacingMergeTree deduplication is
-- resolved here by argMax over updated_at, so disabled rows immediately remove a
-- prefix from the effective dictionary after SYSTEM RELOAD DICTIONARY.
-- ClickHouse 24.11 does not support CREATE OR REPLACE VIEW, so use an explicit
-- DROP + CREATE sequence for idempotent deploys.
DROP TABLE IF EXISTS default.local_networks_enabled;

CREATE VIEW default.local_networks_enabled AS
SELECT
    prefix,
    name,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        prefix,
        argMax(name, updated_at) AS name,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.local_networks
    GROUP BY
        family,
        prefix
)
WHERE enabled_latest = 1;
