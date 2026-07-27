CREATE VIEW IF NOT EXISTS default.net_interface_roles_current
(
    `switch_ip` String,
    `if_index` UInt32,
    `boundary` LowCardinality(String),
    `connectivity` LowCardinality(String),
    `comment` String,
    `updated_by` String,
    `updated_at` DateTime('UTC')
)
AS SELECT
    switch_ip,
    if_index,
    boundary,
    connectivity,
    comment,
    updated_by,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        switch_ip,
        if_index,
        argMax(boundary, updated_at) AS boundary,
        argMax(connectivity, updated_at) AS connectivity,
        argMax(comment, updated_at) AS comment,
        argMax(updated_by, updated_at) AS updated_by,
        argMax(deleted, updated_at) AS deleted,
        max(updated_at) AS updated_at_latest
    FROM default.net_interface_roles
    GROUP BY
        switch_ip,
        if_index
)
WHERE deleted = 0;
