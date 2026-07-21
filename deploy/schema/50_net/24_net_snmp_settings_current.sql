CREATE VIEW IF NOT EXISTS default.net_snmp_settings_current
(
    `settings_id` String,
    `community` String,
    `port` UInt16,
    `timeout_ms` UInt32,
    `retries` UInt8,
    `discover_lookback_hours` UInt16,
    `refresh_interval_sec` UInt32,
    `full_walk_interval_sec` UInt32,
    `enabled` UInt8,
    `auto_enable_new_agents` UInt8,
    `updated_at` DateTime('UTC')
)
AS SELECT
    settings_id,
    community,
    port,
    timeout_ms,
    retries,
    discover_lookback_hours,
    refresh_interval_sec,
    full_walk_interval_sec,
    enabled,
    auto_enable_new_agents,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        settings_id,
        argMax(community, updated_at) AS community,
        argMax(port, updated_at) AS port,
        argMax(timeout_ms, updated_at) AS timeout_ms,
        argMax(retries, updated_at) AS retries,
        argMax(discover_lookback_hours, updated_at) AS discover_lookback_hours,
        argMax(refresh_interval_sec, updated_at) AS refresh_interval_sec,
        argMax(full_walk_interval_sec, updated_at) AS full_walk_interval_sec,
        argMax(enabled, updated_at) AS enabled,
        argMax(auto_enable_new_agents, updated_at) AS auto_enable_new_agents,
        max(updated_at) AS updated_at_latest
    FROM default.net_snmp_settings
    GROUP BY settings_id
);
