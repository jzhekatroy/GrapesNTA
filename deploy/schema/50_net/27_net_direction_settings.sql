CREATE TABLE IF NOT EXISTS default.net_direction_settings
(
    `settings_id` String DEFAULT 'global',
    `direction_mode` LowCardinality(String) DEFAULT 'prefixes',
    `default_boundary` LowCardinality(String) DEFAULT 'unknown',
    `one_sided` LowCardinality(String) DEFAULT 'strict',
    -- What a flow between two networks missing from net_l3_prefixes means.
    -- 'foreign': treat them as somebody else's networks, so the flow is
    -- transit. 'unclassified': admit we do not know, so gaps in the catalog
    -- surface instead of inflating transit. Defaults to the historical
    -- behaviour.
    `unknown_networks` LowCardinality(String) DEFAULT 'foreign',
    `updated_by` String DEFAULT '',
    `updated_at` DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY settings_id
SETTINGS index_granularity = 8192;
