-- Add unknown_networks to net_direction_settings.
--
-- Why: a flow between two networks that are absent from net_l3_prefixes was
-- always recorded as transit. "Not in the catalog" is not the same as "belongs
-- to somebody else", so a forgotten prefix of our own silently turned normal
-- in/out traffic into transit. The setting lets an installation choose whether
-- such flows stay transit (historical behaviour, the default) or are marked
-- unclassified so the gap becomes visible.
--
-- Safe to re-run.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_net_direction_unknown_networks.sql

ALTER TABLE default.net_direction_settings
ADD COLUMN IF NOT EXISTS unknown_networks LowCardinality(String) DEFAULT 'foreign';

-- Older ClickHouse versions drop ordinary views via DROP TABLE, not DROP VIEW.
DROP TABLE IF EXISTS default.net_direction_settings_current;

CREATE VIEW default.net_direction_settings_current
(
    `settings_id` String,
    `direction_mode` LowCardinality(String),
    `default_boundary` LowCardinality(String),
    `one_sided` LowCardinality(String),
    `unknown_networks` LowCardinality(String),
    `updated_by` String,
    `updated_at` DateTime('UTC')
)
AS SELECT
    settings_id,
    direction_mode,
    default_boundary,
    one_sided,
    unknown_networks,
    updated_by,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        settings_id,
        argMax(direction_mode, updated_at) AS direction_mode,
        argMax(default_boundary, updated_at) AS default_boundary,
        argMax(one_sided, updated_at) AS one_sided,
        argMax(unknown_networks, updated_at) AS unknown_networks,
        argMax(updated_by, updated_at) AS updated_by,
        max(updated_at) AS updated_at_latest
    FROM default.net_direction_settings
    GROUP BY settings_id
);
