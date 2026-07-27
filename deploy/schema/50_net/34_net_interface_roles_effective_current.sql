CREATE VIEW IF NOT EXISTS default.net_interface_roles_effective_current
(
    `switch_ip` String,
    `if_index` UInt32,
    `boundary` LowCardinality(String),
    `boundary_source` LowCardinality(String),
    `boundary_rule_id` String,
    `connectivity` LowCardinality(String),
    `connectivity_source` LowCardinality(String),
    `connectivity_rule_id` String,
    `updated_at` DateTime('UTC')
)
AS SELECT
    switch_ip,
    if_index,
    boundary,
    boundary_source,
    boundary_rule_id,
    connectivity,
    connectivity_source,
    connectivity_rule_id,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        switch_ip,
        if_index,
        argMax(boundary, updated_at) AS boundary,
        argMax(boundary_source, updated_at) AS boundary_source,
        argMax(boundary_rule_id, updated_at) AS boundary_rule_id,
        argMax(connectivity, updated_at) AS connectivity,
        argMax(connectivity_source, updated_at) AS connectivity_source,
        argMax(connectivity_rule_id, updated_at) AS connectivity_rule_id,
        max(updated_at) AS updated_at_latest
    FROM default.net_interface_roles_effective
    GROUP BY
        switch_ip,
        if_index
);
