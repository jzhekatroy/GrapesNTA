-- Seed a single 'global' SNMP settings row on a fresh install. Idempotent:
-- re-applying never overwrites an operator-provided community or intervals.
INSERT INTO default.net_snmp_settings
    (settings_id, community, port, timeout_ms, retries,
     discover_lookback_hours, refresh_interval_sec, full_walk_interval_sec,
     enabled, auto_enable_new_agents)
SELECT 'global', '', 161, 2000, 1, 24, 1800, 21600, 1, 0
FROM system.one
WHERE (SELECT count() FROM default.net_snmp_settings WHERE settings_id = 'global') = 0;
