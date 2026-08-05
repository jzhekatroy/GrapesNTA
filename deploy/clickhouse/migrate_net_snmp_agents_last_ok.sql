-- Add last_ok_at — the last poll that actually answered — to net_snmp_agents.
--
-- Why: last_poll_at moves on failures too, so the UI could not tell a fresh
-- catalog from a switch that stopped responding weeks ago. «Последний опрос»
-- looked recent while the data behind it was stale.
--
-- Safe to re-run on existing deployments.
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/migrate_net_snmp_agents_last_ok.sql

ALTER TABLE default.net_snmp_agents
ADD COLUMN IF NOT EXISTS last_ok_at DateTime('UTC') DEFAULT toDateTime(0, 'UTC');

-- Older ClickHouse versions drop ordinary views via DROP TABLE, not DROP VIEW.
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
    tuple_state.14 AS updated_at,
    tuple_state.15 AS last_ok_at
FROM
(
    SELECT
        switch_ip,
        min(first_seen_at) AS first_seen_at,
        -- Single-row pick: avoid per-column argMax ties when discover()+poll
        -- share the same updated_at second (UI showed never while poll was ok).
        -- last_ok_at is appended to the tuple: inserting it in the middle would
        -- shift every existing tuple_state.N above.
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
                updated_at,
                last_ok_at
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

-- Seed last_ok_at from the interface catalog: its updated_at only advances on a
-- successful poll, so it is the closest available proxy for existing agents.
-- Without this the column stays 1970 until each switch is polled again.
INSERT INTO default.net_snmp_agents
(
    switch_ip, display_name, source_ids, snmp_enabled, community_override,
    port_override, timeout_ms_override, retries_override, first_seen_at,
    last_seen_at, last_poll_at, last_full_walk_at, last_poll_status,
    last_poll_error, is_new, updated_at, last_ok_at
)
SELECT
    a.switch_ip,
    a.display_name,
    a.source_ids,
    a.snmp_enabled,
    a.community_override,
    a.port_override,
    a.timeout_ms_override,
    a.retries_override,
    a.first_seen_at,
    a.last_seen_at,
    a.last_poll_at,
    a.last_full_walk_at,
    a.last_poll_status,
    a.last_poll_error,
    a.is_new,
    now() AS updated_at,
    ifNull(i.last_catalog_at, toDateTime(0, 'UTC')) AS last_ok_at
FROM default.net_snmp_agents_current AS a
LEFT JOIN
(
    SELECT switch_ip, max(updated_at) AS last_catalog_at
    FROM default.net_interfaces
    GROUP BY switch_ip
) AS i ON a.switch_ip = i.switch_ip
WHERE a.last_ok_at = toDateTime(0, 'UTC');
