CREATE VIEW IF NOT EXISTS default.net_direction_settings_current
(
    `settings_id` String,
    `direction_mode` LowCardinality(String),
    `default_boundary` LowCardinality(String),
    `one_sided` LowCardinality(String),
    `updated_by` String,
    `updated_at` DateTime('UTC')
)
AS SELECT
    settings_id,
    direction_mode,
    default_boundary,
    one_sided,
    updated_by,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        settings_id,
        argMax(direction_mode, updated_at) AS direction_mode,
        argMax(default_boundary, updated_at) AS default_boundary,
        argMax(one_sided, updated_at) AS one_sided,
        argMax(updated_by, updated_at) AS updated_by,
        max(updated_at) AS updated_at_latest
    FROM default.net_direction_settings
    GROUP BY settings_id
);
