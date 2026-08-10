CREATE VIEW IF NOT EXISTS default.net_clients_enabled
(
    `client_id` LowCardinality(String),
    `display_name` String,
    `comment` String,
    `bind_mode` LowCardinality(String),
    `updated_at` DateTime
)
AS SELECT
    client_id,
    display_name,
    comment,
    bind_mode,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        client_id,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(bind_mode, updated_at) AS bind_mode,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_clients
    GROUP BY client_id
)
WHERE enabled_latest = 1;
