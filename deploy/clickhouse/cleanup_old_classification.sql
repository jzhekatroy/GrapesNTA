-- Step 1: remove legacy classification tables, views, and traffic aggregates.
--
-- Before running:
--   1. Set XDP_CLASSIFIER=0 in /etc/xdpflowd/xdpflowd.env
--   2. sudo systemctl restart xdpflowd
--   3. Verify xdpflowd still writes flows_raw without classifier errors
--
-- Apply:
--   clickhouse-client --host HOST --user USER --password PASS \
--     --multiquery < deploy/clickhouse/cleanup_old_classification.sql
--
-- Does NOT touch: flows_raw, BMP/BGP, DNS, geo tables.

-- 1. Materialized views first
DROP TABLE IF EXISTS default.traffic_direction_1m_mv;
DROP TABLE IF EXISTS default.traffic_customer_1m_mv;
DROP TABLE IF EXISTS default.traffic_uplink_1m_mv;
DROP TABLE IF EXISTS default.traffic_chart_1m_mv;
DROP TABLE IF EXISTS default.traffic_1m_mv;
DROP TABLE IF EXISTS default.traffic_asn_pair_1m_mv;

-- 2. Aggregate target tables
DROP TABLE IF EXISTS default.traffic_direction_1m;
DROP TABLE IF EXISTS default.traffic_customer_1m;
DROP TABLE IF EXISTS default.traffic_uplink_1m;
DROP TABLE IF EXISTS default.traffic_chart_1m;
DROP TABLE IF EXISTS default.traffic_1m;
DROP TABLE IF EXISTS default.traffic_asn_pair_1m;

-- 3. Legacy enabled views
DROP VIEW IF EXISTS default.local_networks_enabled;
DROP VIEW IF EXISTS default.local_asns_enabled;
DROP VIEW IF EXISTS default.local_operators_enabled;
DROP VIEW IF EXISTS default.vlan_map_enabled;

-- 4. Legacy config tables
DROP TABLE IF EXISTS default.local_networks;
DROP TABLE IF EXISTS default.local_asns;
DROP TABLE IF EXISTS default.local_operators;
DROP TABLE IF EXISTS default.vlan_map;
