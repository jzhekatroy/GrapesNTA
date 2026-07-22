-- SNMP v2c agent and interface catalog.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_snmp_interfaces.sql
--
-- Secrets are not seeded here. Set the global community after applying this
-- file, or configure a per-switch override in net_snmp_agents.

CREATE TABLE IF NOT EXISTS default.net_snmp_settings
(
    settings_id             String DEFAULT 'global',
    community               String DEFAULT '',
    port                    UInt16 DEFAULT 161,
    timeout_ms              UInt32 DEFAULT 2000,
    retries                 UInt8 DEFAULT 1,
    discover_lookback_hours UInt16 DEFAULT 1,
    refresh_interval_sec    UInt32 DEFAULT 1800,
    full_walk_interval_sec  UInt32 DEFAULT 21600,
    enabled                 UInt8 DEFAULT 1,
    auto_enable_new_agents  UInt8 DEFAULT 0,
    updated_at              DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY settings_id
SETTINGS index_granularity = 8192;

-- Upgrades (run missing columns once; many CH builds lack IF NOT EXISTS):
--   ALTER TABLE default.net_snmp_settings
--       ADD COLUMN auto_enable_new_agents UInt8 DEFAULT 0;
-- Then re-apply this file so *_current views are recreated.
-- If net_interfaces_dict depends on net_interfaces_current, drop/recreate the
-- dictionary after this file (see apply_net_snmp_interfaces_dict.sh).


-- Older ClickHouse versions drop ordinary views via DROP TABLE, not DROP VIEW.
DROP TABLE IF EXISTS default.net_snmp_settings_current;

CREATE VIEW default.net_snmp_settings_current AS
SELECT
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

CREATE TABLE IF NOT EXISTS default.net_snmp_agents
(
    switch_ip            String,
    display_name         String DEFAULT '',
    source_ids           Array(String) DEFAULT [],
    snmp_enabled         UInt8 DEFAULT 0,
    community_override   String DEFAULT '',
    port_override        UInt16 DEFAULT 0,
    timeout_ms_override  UInt32 DEFAULT 0,
    retries_override     UInt8 DEFAULT 0,
    first_seen_at        DateTime('UTC'),
    last_seen_at         DateTime('UTC'),
    last_poll_at         DateTime('UTC') DEFAULT toDateTime(0, 'UTC'),
    last_full_walk_at    DateTime('UTC') DEFAULT toDateTime(0, 'UTC'),
    last_poll_status     LowCardinality(String) DEFAULT 'never',
    last_poll_error      String DEFAULT '',
    is_new               UInt8 DEFAULT 1,
    updated_at           DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY switch_ip
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.net_snmp_agents_current;

CREATE VIEW default.net_snmp_agents_current AS
SELECT
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

CREATE TABLE IF NOT EXISTS default.net_interfaces
(
    switch_ip          String,
    if_index           UInt32,
    if_name            String DEFAULT '',
    if_alias           String DEFAULT '',
    if_descr           String DEFAULT '',
    if_high_speed_mbps UInt32 DEFAULT 0,
    if_speed_bps       UInt64 DEFAULT 0,
    updated_at         DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (switch_ip, if_index)
SETTINGS index_granularity = 8192;

DROP TABLE IF EXISTS default.net_interfaces_current;

CREATE VIEW default.net_interfaces_current AS
SELECT
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

-- Seed only an empty installation. Re-applying DDL must not overwrite an
-- operator-provided community or polling intervals.
INSERT INTO default.net_snmp_settings
    (settings_id, community, port, timeout_ms, retries,
     discover_lookback_hours, refresh_interval_sec, full_walk_interval_sec,
     enabled, auto_enable_new_agents)
SELECT
    'global', '', 161, 2000, 1, 1, 1800, 21600, 1, 0
FROM system.one
WHERE
(
    SELECT count()
    FROM default.net_snmp_settings
    WHERE settings_id = 'global'
) = 0;

-- Dictionary DDL is in net_snmp_interfaces_dict.sql and must be applied over
-- the local native ClickHouse interface (dictionaries are rejected by some
-- external HTTP proxies on :6124).
