-- Register the NetFlow v9 receiver source in the catalog.
--
-- Apply after net_flow_sources.sql:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_flow_sources_netflow.sql
--
-- source_id MUST match FC_NETFLOW_SOURCE_ID in the flowcollectord env on the host.
-- include_in_total = 1 because this is a separate observation point.
-- Switch to 0 later if the same traffic is already counted via XDP or sFlow.

INSERT INTO default.net_flow_sources
    (source_id, display_name, source_type, collector_id, location,
     description, include_in_total, enabled, updated_at)
SELECT
    'netflow-default',
    'Default NetFlow v9',
    'netflow',
    '',
    '',
    'NetFlow v9 receiver (flowcollectord)',
    1,
    1,
    now();
