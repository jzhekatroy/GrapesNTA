-- Rebuild traffic aggregates with source_id dimension.
-- Old aggregate rows are discarded (SummingMergeTree ORDER BY key changed).
--
-- Apply in order:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_flow_sources.sql
--   clickhouse-client ... --multiquery < deploy/clickhouse/flows_raw_source_id.sql
--   clickhouse-client ... --multiquery < deploy/clickhouse/apply_flow_sources.sql
--   for f in traffic_direction_1m.sql traffic_role_1m.sql traffic_entity_1m.sql \
--            traffic_vlan_1m.sql traffic_protocol_1m.sql traffic_service_1m.sql \
--            traffic_dashboard_1m.sql traffic_dashboard_1d.sql; do
--     clickhouse-client ... --multiquery < deploy/clickhouse/$f
--   done

DROP TABLE IF EXISTS default.traffic_direction_1m_mv;
DROP TABLE IF EXISTS default.traffic_role_1m_mv;
DROP TABLE IF EXISTS default.traffic_entity_1m_mv;
DROP TABLE IF EXISTS default.traffic_vlan_1m_mv;
DROP TABLE IF EXISTS default.traffic_protocol_1m_mv;
DROP TABLE IF EXISTS default.traffic_service_1m_mv;
DROP TABLE IF EXISTS default.traffic_dashboard_1m_mv;
DROP TABLE IF EXISTS default.traffic_dashboard_1h_mv;
DROP TABLE IF EXISTS default.traffic_dashboard_1d_mv;

DROP TABLE IF EXISTS default.traffic_direction_1m;
DROP TABLE IF EXISTS default.traffic_role_1m;
DROP TABLE IF EXISTS default.traffic_entity_1m;
DROP TABLE IF EXISTS default.traffic_vlan_1m;
DROP TABLE IF EXISTS default.traffic_protocol_1m;
DROP TABLE IF EXISTS default.traffic_service_1m;
DROP TABLE IF EXISTS default.traffic_dashboard_1m;
DROP TABLE IF EXISTS default.traffic_dashboard_1h;
DROP TABLE IF EXISTS default.traffic_dashboard_1d;
