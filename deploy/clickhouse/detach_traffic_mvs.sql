-- Detach all traffic_* materialized views on production ingest.
--
-- Sync MV fan-out on INSERT flows_raw blocks xdpflowd writes (lag_segments,
-- writer_lag_rows). Aggregate tables are filled by async rollups instead:
--   scripts/traffic_rollup_async.py + deploy/systemd/traffic-rollups.timer
--
-- Safe to re-run: DETACH is idempotent when the view is already detached.
-- Apply after deploy/clickhouse/traffic_*.sql (tables only, no MV CREATE).

DETACH TABLE IF EXISTS default.traffic_dashboard_1m_mv;
DETACH TABLE IF EXISTS default.traffic_dashboard_1h_mv;
DETACH TABLE IF EXISTS default.traffic_dashboard_1d_mv;
DETACH TABLE IF EXISTS default.traffic_protocol_1m_mv;
DETACH TABLE IF EXISTS default.traffic_direction_1m_mv;
DETACH TABLE IF EXISTS default.traffic_role_1m_mv;
DETACH TABLE IF EXISTS default.traffic_entity_1m_mv;
DETACH TABLE IF EXISTS default.traffic_vlan_1m_mv;
DETACH TABLE IF EXISTS default.traffic_country_1m_mv;
DETACH TABLE IF EXISTS default.traffic_service_1m_mv;
DETACH TABLE IF EXISTS default.traffic_unknown_port_1m_mv;
DETACH TABLE IF EXISTS default.traffic_talker_1m_mv;
DETACH TABLE IF EXISTS default.traffic_pair_1m_mv;
DETACH TABLE IF EXISTS default.traffic_talker_1h_mv;
DETACH TABLE IF EXISTS default.traffic_pair_1h_mv;
