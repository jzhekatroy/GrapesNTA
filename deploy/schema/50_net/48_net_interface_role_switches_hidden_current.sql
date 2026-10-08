CREATE VIEW IF NOT EXISTS default.net_interface_role_switches_hidden_current
(
    `switch_ip` String,
    `display_name` String,
    `hidden` UInt8,
    `updated_by` String,
    `updated_at` DateTime('UTC')
)
AS SELECT
    switch_ip,
    display_name,
    hidden,
    updated_by,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        switch_ip,
        argMax(display_name, updated_at) AS display_name,
        argMax(hidden, updated_at) AS hidden,
        argMax(updated_by, updated_at) AS updated_by,
        max(updated_at) AS updated_at_latest
    FROM default.net_interface_role_switches_hidden
    GROUP BY switch_ip
);
