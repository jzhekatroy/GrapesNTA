CREATE VIEW IF NOT EXISTS default.net_interfaces_current
(
    `switch_ip` String,
    `if_index` UInt32,
    `if_name` String,
    `if_alias` String,
    `if_descr` String,
    `if_high_speed_mbps` UInt32,
    `if_speed_bps` UInt64,
    `updated_at` DateTime('UTC')
)
AS SELECT
    switch_ip,
    if_index,
    if_name,
    if_alias,
    if_descr,
    if_high_speed_mbps,
    if_speed_bps,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        switch_ip,
        if_index,
        argMax(if_name, updated_at) AS if_name,
        argMax(if_alias, updated_at) AS if_alias,
        argMax(if_descr, updated_at) AS if_descr,
        argMax(if_high_speed_mbps, updated_at) AS if_high_speed_mbps,
        argMax(if_speed_bps, updated_at) AS if_speed_bps,
        max(updated_at) AS updated_at_latest
    FROM default.net_interfaces
    GROUP BY
        switch_ip,
        if_index
);
