CREATE VIEW IF NOT EXISTS default.net_l3_prefixes_enabled
(
    `prefix` String,
    `family` UInt8,
    `entity_id` String,
    `role` String,
    `origin_asn` UInt32,
    `display_name` String,
    `comment` String,
    `source` String,
    `updated_at` DateTime
)
AS SELECT
    prefix,
    family,
    entity_id,
    role,
    origin_asn,
    display_name,
    comment,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        prefix,
        family,
        argMax(entity_id, updated_at) AS entity_id,
        argMax(role, updated_at) AS role,
        argMax(origin_asn, updated_at) AS origin_asn,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_l3_prefixes
    GROUP BY
        family,
        prefix
)
WHERE enabled_latest = 1;
