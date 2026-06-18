-- Register sel as a separate collector with xdp-sel + dns-sel sources.
-- Safe to re-run: ReplacingMergeTree keeps latest row per key.
--
--   clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '...' \
--     --multiquery < deploy/clickhouse/register_sel_collector.sql

INSERT INTO default.net_collectors
    (collector_id, location_id, display_name, hostname, comment, enabled, updated_at)
VALUES
    ('sel', 'piterix', 'sel', '95.215.0.26',
     'ConnectX-4 mirror enp4s0np0 — xdpflowd + dnsflowd', 1, now());

INSERT INTO default.net_flow_sources
    (source_id, display_name, source_type, collector_id, location,
     description, include_in_total, enabled, updated_at)
VALUES
    ('xdp-sel', 'sel XDP mirror', 'xdp', 'sel', 'piterix',
     'sel enp4s0np0 xdpflowd native XDP', 0, 1, now());

INSERT INTO default.net_flow_sources
    (source_id, display_name, source_type, collector_id, location,
     description, include_in_total, enabled, updated_at)
VALUES
    ('dns-sel', 'sel DNS mirror', 'dns', 'sel', 'piterix',
     'sel enp4s0np0 dnsflowd AF_PACKET', 0, 1, now());
