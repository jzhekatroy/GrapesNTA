-- Register the sFlow v5 receiver source in the catalog.
--
-- Apply after net_flow_sources.sql:
--   clickhouse-client ... --multiquery < deploy/clickhouse/net_flow_sources_sflow.sql
--
-- source_id MUST match FC_SFLOW_SOURCE_ID in the flowcollectord env on the host.
-- include_in_total = 1 because the sFlow point is a separate observation point
-- (no overlap with the XDP mirror). Switch to 0 later if overlap appears.

INSERT INTO default.net_flow_sources
    (source_id, display_name, source_type, collector_id, location,
     description, include_in_total, enabled, updated_at)
SELECT
    'sflow-default',
    'Default sFlow v5',
    'sflow',
    '',
    '',
    'sFlow v5 receiver (flowcollectord)',
    1,
    1,
    now();
