-- Collector health snapshots: cumulative counters written periodically by
-- xdpflowd / flowcollectord for NTAdmin completeness checks (no Prometheus).
--
-- Apply:
--   clickhouse-client ... --multiquery < deploy/clickhouse/collector_health_snapshots.sql
--
-- UI / alerts: diff counters over a window (e.g. 5m) per source_id:
--   received  ~= xdp_total_packets / xdp_total_bytes
--   written   ~= flow_packets_acked / flow_bytes_acked (spool)
--              or flow_packets_written / flow_bytes_written (direct)
--   lost      ~= xdp_map_full delta, ch_queue_drops delta, udp_queue_drops delta

CREATE TABLE IF NOT EXISTS default.collector_health_snapshots
(
    ts DateTime64(3, 'UTC'),
    collector_id String,
    source_id String,
    daemon LowCardinality(String),
    hostname String DEFAULT hostName(),
    iface String DEFAULT '',

    xdp_total_packets UInt64 DEFAULT 0,
    xdp_total_bytes UInt64 DEFAULT 0,
    xdp_map_full UInt64 DEFAULT 0,
    xdp_parse_errors UInt64 DEFAULT 0,
    xdp_non_ip_pass UInt64 DEFAULT 0,
    nic_rx_packets UInt64 DEFAULT 0,
    nic_rx_bytes UInt64 DEFAULT 0,

    datagrams UInt64 DEFAULT 0,
    records_parsed UInt64 DEFAULT 0,
    receiver_parse_errors UInt64 DEFAULT 0,
    udp_queue_drops UInt64 DEFAULT 0,

    ch_mode LowCardinality(String) DEFAULT '',
    records_queued UInt64 DEFAULT 0,
    records_written UInt64 DEFAULT 0,
    records_spooled UInt64 DEFAULT 0,
    records_acked UInt64 DEFAULT 0,
    flow_packets_queued UInt64 DEFAULT 0,
    flow_bytes_queued UInt64 DEFAULT 0,
    flow_packets_written UInt64 DEFAULT 0,
    flow_bytes_written UInt64 DEFAULT 0,
    flow_packets_spooled UInt64 DEFAULT 0,
    flow_bytes_spooled UInt64 DEFAULT 0,
    flow_packets_acked UInt64 DEFAULT 0,
    flow_bytes_acked UInt64 DEFAULT 0,
    insert_errs UInt64 DEFAULT 0,
    ch_queue_drops UInt64 DEFAULT 0,
    lag_segments Int64 DEFAULT 0,
    drainer_progress_age_sec Float64 DEFAULT 0,

    flow_rows_excluded UInt64 DEFAULT 0,
    flow_packets_excluded UInt64 DEFAULT 0,
    flow_bytes_excluded UInt64 DEFAULT 0,
    exclusion_rules UInt32 DEFAULT 0,

    status LowCardinality(String) DEFAULT 'ok',
    status_reasons Array(String) DEFAULT []
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (source_id, ts)
TTL toDateTime(ts) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

ALTER TABLE default.collector_health_snapshots
    ADD COLUMN IF NOT EXISTS xdp_total_bytes UInt64 DEFAULT 0 AFTER xdp_total_packets,
    ADD COLUMN IF NOT EXISTS flow_packets_queued UInt64 DEFAULT 0 AFTER records_acked,
    ADD COLUMN IF NOT EXISTS flow_bytes_queued UInt64 DEFAULT 0 AFTER flow_packets_queued,
    ADD COLUMN IF NOT EXISTS flow_packets_written UInt64 DEFAULT 0 AFTER flow_bytes_queued,
    ADD COLUMN IF NOT EXISTS flow_bytes_written UInt64 DEFAULT 0 AFTER flow_packets_written,
    ADD COLUMN IF NOT EXISTS flow_packets_spooled UInt64 DEFAULT 0 AFTER flow_bytes_written,
    ADD COLUMN IF NOT EXISTS flow_bytes_spooled UInt64 DEFAULT 0 AFTER flow_packets_spooled,
    ADD COLUMN IF NOT EXISTS flow_packets_acked UInt64 DEFAULT 0 AFTER flow_bytes_spooled,
    ADD COLUMN IF NOT EXISTS flow_bytes_acked UInt64 DEFAULT 0 AFTER flow_packets_acked,
    ADD COLUMN IF NOT EXISTS flow_rows_excluded UInt64 DEFAULT 0 AFTER drainer_progress_age_sec,
    ADD COLUMN IF NOT EXISTS flow_packets_excluded UInt64 DEFAULT 0 AFTER flow_rows_excluded,
    ADD COLUMN IF NOT EXISTS flow_bytes_excluded UInt64 DEFAULT 0 AFTER flow_packets_excluded,
    ADD COLUMN IF NOT EXISTS exclusion_rules UInt32 DEFAULT 0 AFTER flow_bytes_excluded;
