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
    discover_lookback_hours UInt16 DEFAULT 24,
    refresh_interval_sec    UInt32 DEFAULT 1800,
    full_walk_interval_sec  UInt32 DEFAULT 21600,
    enabled                 UInt8 DEFAULT 1,
    updated_at              DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY settings_id
SETTINGS index_granularity = 8192;

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
        max(updated_at) AS updated_at_latest
    FROM default.net_snmp_settings
    GROUP BY settings_id
);

-- Seed only an empty installation. Re-applying DDL must not overwrite an
-- operator-provided community or polling intervals.
INSERT INTO default.net_snmp_settings
    (settings_id, community, port, timeout_ms, retries,
     discover_lookback_hours, refresh_interval_sec, full_walk_interval_sec,
     enabled)
SELECT
    'global', '', 161, 2000, 1, 24, 1800, 21600, 1
WHERE NOT EXISTS
(
    SELECT 1
    FROM default.net_snmp_settings
    WHERE settings_id = 'global'
);

CREATE TABLE IF NOT EXISTS default.net_snmp_agents
(
    switch_ip            String,
    display_name         String DEFAULT '',
    source_ids           Array(String) DEFAULT [],
    snmp_enabled         UInt8 DEFAULT 1,
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
    display_name,
    source_ids,
    snmp_enabled,
    community_override,
    port_override,
    timeout_ms_override,
    retries_override,
    first_seen_at,
    last_seen_at,
    last_poll_at,
    last_full_walk_at,
    last_poll_status,
    last_poll_error,
    is_new,
    updated_at_latest AS updated_at
FROM
(
    SELECT
        switch_ip,
        argMax(display_name, updated_at) AS display_name,
        argMax(source_ids, updated_at) AS source_ids,
        argMax(snmp_enabled, updated_at) AS snmp_enabled,
        argMax(community_override, updated_at) AS community_override,
        argMax(port_override, updated_at) AS port_override,
        argMax(timeout_ms_override, updated_at) AS timeout_ms_override,
        argMax(retries_override, updated_at) AS retries_override,
        min(first_seen_at) AS first_seen_at,
        argMax(last_seen_at, updated_at) AS last_seen_at,
        argMax(last_poll_at, updated_at) AS last_poll_at,
        argMax(last_full_walk_at, updated_at) AS last_full_walk_at,
        argMax(last_poll_status, updated_at) AS last_poll_status,
        argMax(last_poll_error, updated_at) AS last_poll_error,
        argMax(is_new, updated_at) AS is_new,
        max(updated_at) AS updated_at_latest
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

DROP DICTIONARY IF EXISTS default.net_interfaces_dict;

-- The dictionary reads from this ClickHouse server over its local native port.
-- If the local `default` user is disabled, create this dictionary with an
-- explicitly configured read-only dictionary user instead.
CREATE DICTIONARY default.net_interfaces_dict
(
    switch_ip          String,
    if_index           UInt32,
    if_name            String DEFAULT '',
    if_alias           String DEFAULT '',
    if_descr           String DEFAULT '',
    if_high_speed_mbps UInt32 DEFAULT 0,
    if_speed_bps       UInt64 DEFAULT 0
)
PRIMARY KEY switch_ip, if_index
SOURCE(CLICKHOUSE(
    HOST '127.0.0.1'
    PORT 9000
    USER 'default'
    PASSWORD ''
    DB 'default'
    TABLE 'net_interfaces_current'
))
LIFETIME(MIN 60 MAX 120)
LAYOUT(COMPLEX_KEY_HASHED());
