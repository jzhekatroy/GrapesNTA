CREATE VIEW IF NOT EXISTS default.net_entities_enabled
(
    `entity_id` LowCardinality(String),
    `display_name` String,
    `comment` String,
    `source` String,
    `updated_at` DateTime
)
AS SELECT
    entity_id,
    display_name,
    comment,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        entity_id,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_entities
    GROUP BY entity_id
)
WHERE enabled_latest = 1;
