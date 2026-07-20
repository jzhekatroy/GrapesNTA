CREATE VIEW IF NOT EXISTS default.net_flow_sources_enabled
(
    `source_id` String,
    `display_name` String,
    `source_type` String,
    `collector_id` String,
    `location` String,
    `description` String,
    `include_in_total` UInt8,
    `updated_at` DateTime('UTC')
)
AS SELECT
    source_id,
    display_name,
    source_type,
    collector_id,
    location,
    description,
    include_in_total,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        source_id,
        argMax(display_name, updated_at) AS display_name,
        argMax(source_type, updated_at) AS source_type,
        argMax(collector_id, updated_at) AS collector_id,
        argMax(location, updated_at) AS location,
        argMax(description, updated_at) AS description,
        argMax(include_in_total, updated_at) AS include_in_total,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_flow_sources
    GROUP BY source_id
)
WHERE enabled_latest = 1;
