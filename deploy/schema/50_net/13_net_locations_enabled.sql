CREATE VIEW IF NOT EXISTS default.net_locations_enabled
(
    `location_id` String,
    `display_name` String,
    `city` String,
    `country` String,
    `comment` String,
    `updated_at` DateTime('UTC')
)
AS SELECT
    location_id,
    display_name,
    city,
    country,
    comment,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        location_id,
        argMax(display_name, updated_at) AS display_name,
        argMax(city, updated_at) AS city,
        argMax(country, updated_at) AS country,
        argMax(comment, updated_at) AS comment,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_locations
    GROUP BY location_id
)
WHERE enabled_latest = 1;
