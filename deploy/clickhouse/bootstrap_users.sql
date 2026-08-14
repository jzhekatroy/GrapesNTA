-- Bootstrap ClickHouse users for a fresh GrapesNTA install.
-- Run as a user with GRANT OPTION (default / develop), AFTER ./deploy/schema/apply.sh.
--
-- Replace the three passwords, then:
--   clickhouse-client --host HOST --port 9000 --user default --password '...' \
--     --multiquery < deploy/clickhouse/bootstrap_users.sql
--
-- Overflow mode MUST stay 'throw'. Never use 'break' — it silently truncates
-- aggregates and looks like a successful query.

CREATE USER IF NOT EXISTS collector_write IDENTIFIED BY 'CHANGE_ME_COLLECTOR';

CREATE USER IF NOT EXISTS ui_read IDENTIFIED BY 'CHANGE_ME_UI_READ'
  SETTINGS
    max_execution_time = 120,
    timeout_overflow_mode = 'throw',
    max_rows_to_read = 0,
    max_bytes_to_read = 0,
    read_overflow_mode = 'throw',
    max_result_rows = 0,
    result_overflow_mode = 'throw';

CREATE USER IF NOT EXISTS ui_admin IDENTIFIED BY 'CHANGE_ME_UI_ADMIN'
  SETTINGS
    max_execution_time = 30,
    timeout_overflow_mode = 'throw',
    max_rows_to_read = 100000000,
    max_bytes_to_read = 20000000000,
    read_overflow_mode = 'throw',
    max_result_rows = 500000,
    result_overflow_mode = 'throw';

GRANT INSERT ON default.flows_raw TO collector_write;
GRANT INSERT ON default.dns_log TO collector_write;
GRANT INSERT ON default.dns_answers TO collector_write;
GRANT INSERT ON default.bmp_peers TO collector_write;
GRANT INSERT ON default.bmp_route_events TO collector_write;
GRANT INSERT ON default.bgp_updates_1m TO collector_write;
GRANT INSERT ON default.collector_health_snapshots TO collector_write;
-- Classifier on the collector reads L3/L2/BGP catalogs over the same DSN.
GRANT SELECT ON default.* TO collector_write;

GRANT SELECT ON default.* TO ui_read;
GRANT SELECT ON system.tables TO ui_read;
GRANT SELECT ON system.columns TO ui_read;
GRANT SELECT ON system.dictionaries TO ui_read;
GRANT dictGet ON default.geo_country_dict TO ui_read;
GRANT dictGet ON default.bgp_origin_asn_dict TO ui_read;
GRANT dictGet ON default.net_interfaces_dict TO ui_read;

GRANT SELECT, INSERT, CREATE TABLE, ALTER TABLE, DROP TABLE, ALTER DELETE, TRUNCATE ON default.* TO ui_admin;
GRANT CREATE DICTIONARY, DROP DICTIONARY ON default.* TO ui_admin;
GRANT SYSTEM RELOAD DICTIONARY ON *.* TO ui_admin;
GRANT SELECT ON system.* TO ui_admin;
GRANT dictGet ON default.geo_country_dict TO ui_admin;
GRANT dictGet ON default.bgp_origin_asn_dict TO ui_admin;
GRANT dictGet ON default.net_interfaces_dict TO ui_admin;
