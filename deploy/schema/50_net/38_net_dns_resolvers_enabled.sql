CREATE VIEW IF NOT EXISTS default.net_dns_resolvers_enabled
(
    `resolver_id` String,
    `prefix` String,
    `family` UInt8,
    `role` String,
    `display_name` String,
    `comment` String,
    `source` String,
    `updated_at` DateTime
)
AS SELECT
    resolver_id,
    prefix,
    family,
    role,
    display_name,
    comment,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        resolver_id,
        argMax(prefix, updated_at) AS prefix,
        argMax(family, updated_at) AS family,
        argMax(role, updated_at) AS role,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_dns_resolvers
    GROUP BY resolver_id
)
WHERE enabled_latest = 1;
