CREATE VIEW IF NOT EXISTS default.net_interface_role_rules_current
(
    `rule_id` String,
    `priority` UInt32,
    `match_field` LowCardinality(String),
    `pattern` String,
    `case_sensitive` UInt8,
    `min_speed_mbps` UInt32,
    `max_speed_mbps` UInt32,
    `boundary` LowCardinality(String),
    `connectivity` LowCardinality(String),
    `comment` String,
    `enabled` UInt8,
    `updated_at` DateTime('UTC')
)
AS SELECT
    rule_id,
    priority,
    match_field,
    pattern,
    case_sensitive,
    min_speed_mbps,
    max_speed_mbps,
    boundary,
    connectivity,
    comment,
    enabled,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        rule_id,
        argMax(priority, updated_at) AS priority,
        argMax(match_field, updated_at) AS match_field,
        argMax(pattern, updated_at) AS pattern,
        argMax(case_sensitive, updated_at) AS case_sensitive,
        argMax(min_speed_mbps, updated_at) AS min_speed_mbps,
        argMax(max_speed_mbps, updated_at) AS max_speed_mbps,
        argMax(boundary, updated_at) AS boundary,
        argMax(connectivity, updated_at) AS connectivity,
        argMax(comment, updated_at) AS comment,
        argMax(enabled, updated_at) AS enabled,
        argMax(deleted, updated_at) AS deleted,
        max(updated_at) AS updated_at_latest
    FROM default.net_interface_role_rules
    GROUP BY rule_id
)
WHERE deleted = 0;
