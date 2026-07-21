CREATE VIEW IF NOT EXISTS default.net_snmp_agents_current
(
    `switch_ip` String,
    `display_name` String,
    `source_ids` Array(String),
    `snmp_enabled` UInt8,
    `community_override` String,
    `port_override` UInt16,
    `timeout_ms_override` UInt32,
    `retries_override` UInt8,
    `first_seen_at` DateTime('UTC'),
    `last_seen_at` DateTime('UTC'),
    `last_poll_at` DateTime('UTC'),
    `last_full_walk_at` DateTime('UTC'),
    `last_poll_status` LowCardinality(String),
    `last_poll_error` String,
    `is_new` UInt8,
    `updated_at` DateTime('UTC')
)
AS SELECT
    switch_ip,
    tuple_state.1 AS display_name,
    tuple_state.2 AS source_ids,
    tuple_state.3 AS snmp_enabled,
    tuple_state.4 AS community_override,
    tuple_state.5 AS port_override,
    tuple_state.6 AS timeout_ms_override,
    tuple_state.7 AS retries_override,
    first_seen_at,
    tuple_state.8 AS last_seen_at,
    tuple_state.9 AS last_poll_at,
    tuple_state.10 AS last_full_walk_at,
    tuple_state.11 AS last_poll_status,
    tuple_state.12 AS last_poll_error,
    tuple_state.13 AS is_new,
    tuple_state.14 AS updated_at
FROM
(
    SELECT
        switch_ip,
        min(first_seen_at) AS first_seen_at,
        -- Single-row pick: avoid per-column argMax ties when discover()+poll
        -- share the same updated_at second (UI showed never while poll was ok).
        argMax(
            tuple(
                display_name,
                source_ids,
                snmp_enabled,
                community_override,
                port_override,
                timeout_ms_override,
                retries_override,
                last_seen_at,
                last_poll_at,
                last_full_walk_at,
                last_poll_status,
                last_poll_error,
                is_new,
                updated_at
            ),
            (
                updated_at,
                multiIf(
                    last_poll_status = 'ok', 3,
                    last_poll_status IN ('timeout', 'auth_error', 'error', 'config_error'), 2,
                    last_poll_status = 'queued', 1,
                    0
                )
            )
        ) AS tuple_state
    FROM default.net_snmp_agents
    GROUP BY switch_ip
);
