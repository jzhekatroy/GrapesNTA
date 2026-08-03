CREATE VIEW IF NOT EXISTS default.net_flow_exclusions_enabled
(
    `rule_id` String,
    `prefix` String,
    `family` UInt8,
    `match_side` String,
    `proto` UInt8,
    `port_from` UInt16,
    `port_to` UInt16,
    `port_side` String,
    `vlan_id` UInt16,
    `switch_ip` String,
    `if_index` UInt32,
    `source_id` String,
    `display_name` String,
    `comment` String,
    `source` String,
    `updated_at` DateTime
)
AS SELECT
    rule_id,
    prefix,
    family,
    match_side,
    proto,
    port_from,
    port_to,
    port_side,
    vlan_id,
    switch_ip,
    if_index,
    source_id,
    display_name,
    comment,
    source,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        rule_id,
        argMax(prefix, updated_at) AS prefix,
        argMax(family, updated_at) AS family,
        argMax(match_side, updated_at) AS match_side,
        argMax(proto, updated_at) AS proto,
        argMax(port_from, updated_at) AS port_from,
        argMax(port_to, updated_at) AS port_to,
        argMax(port_side, updated_at) AS port_side,
        argMax(vlan_id, updated_at) AS vlan_id,
        argMax(switch_ip, updated_at) AS switch_ip,
        argMax(if_index, updated_at) AS if_index,
        argMax(source_id, updated_at) AS source_id,
        argMax(display_name, updated_at) AS display_name,
        argMax(comment, updated_at) AS comment,
        argMax(source, updated_at) AS source,
        argMax(enabled, updated_at) AS enabled_latest,
        max(updated_at) AS updated_at_latest
    FROM default.net_flow_exclusions
    GROUP BY rule_id
)
WHERE enabled_latest = 1;
