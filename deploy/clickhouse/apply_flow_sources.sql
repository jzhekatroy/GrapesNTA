-- Rebuild traffic aggregates with source_id dimension.
-- Old aggregate rows are discarded (SummingMergeTree ORDER BY key changed).
--
-- Apply in order:
--   ./deploy/schema/apply.sh 50_net 60_traffic
--   clickhouse-client ... --multiquery < deploy/clickhouse/flows_raw_source_id.sql
--   clickhouse-client ... --multiquery < deploy/clickhouse/apply_flow_sources.sql
--   ./deploy/schema/apply.sh 60_traffic
--   clickhouse-client ... --multiquery < deploy/clickhouse/detach_traffic_mvs.sql

DROP TABLE IF EXISTS default.traffic_direction_1m_mv;
DROP TABLE IF EXISTS default.traffic_role_1m_mv;
DROP TABLE IF EXISTS default.traffic_entity_1m_mv;
DROP TABLE IF EXISTS default.traffic_vlan_1m_mv;
DROP TABLE IF EXISTS default.traffic_protocol_1m_mv;
DROP TABLE IF EXISTS default.traffic_service_1m_mv;
DROP TABLE IF EXISTS default.traffic_unknown_port_1m_mv;
DROP TABLE IF EXISTS default.traffic_country_1m_mv;
DROP TABLE IF EXISTS default.traffic_talker_1m_mv;
DROP TABLE IF EXISTS default.traffic_pair_1m_mv;
DROP TABLE IF EXISTS default.traffic_talker_1h_mv;
DROP TABLE IF EXISTS default.traffic_pair_1h_mv;
DROP TABLE IF EXISTS default.traffic_dashboard_1m_mv;
DROP TABLE IF EXISTS default.traffic_dashboard_1h_mv;
DROP TABLE IF EXISTS default.traffic_dashboard_1d_mv;

DROP TABLE IF EXISTS default.traffic_direction_1m;
DROP TABLE IF EXISTS default.traffic_role_1m;
DROP TABLE IF EXISTS default.traffic_entity_1m;
DROP TABLE IF EXISTS default.traffic_vlan_1m;
DROP TABLE IF EXISTS default.traffic_protocol_1m;
DROP TABLE IF EXISTS default.traffic_service_1m;
DROP TABLE IF EXISTS default.traffic_unknown_port_1m;
DROP TABLE IF EXISTS default.traffic_country_1m;
DROP TABLE IF EXISTS default.traffic_talker_1m;
DROP TABLE IF EXISTS default.traffic_pair_1m;
DROP TABLE IF EXISTS default.traffic_talker_1h;
DROP TABLE IF EXISTS default.traffic_pair_1h;
DROP TABLE IF EXISTS default.traffic_dashboard_1m;
DROP TABLE IF EXISTS default.traffic_dashboard_1h;
DROP TABLE IF EXISTS default.traffic_dashboard_1d;
