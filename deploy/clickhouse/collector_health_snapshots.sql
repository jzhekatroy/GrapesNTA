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
    nic_rx_dropped UInt64 DEFAULT 0,
    nic_rx_errors UInt64 DEFAULT 0,
    nic_rx_missed UInt64 DEFAULT 0,
    nic_rx_fifo_errors UInt64 DEFAULT 0,

    -- Wire-side numbers from the driver stat table. Under XDP the netdev
    -- counters above see only what was passed upstack, so these are the only
    -- honest answer to "how much actually arrived on the port".
    phy_rx_packets UInt64 DEFAULT 0,
    phy_rx_discards UInt64 DEFAULT 0,
    phy_counter_source LowCardinality(String) DEFAULT '',

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
    spool_corruption_frames UInt64 DEFAULT 0,
    spool_corruption_bytes UInt64 DEFAULT 0,

    flow_rows_excluded UInt64 DEFAULT 0,
    flow_packets_excluded UInt64 DEFAULT 0,
    flow_bytes_excluded UInt64 DEFAULT 0,
    exclusion_rules UInt32 DEFAULT 0,

    -- NetFlow v9 export leg. UDP acknowledges nothing, so these are the last
    -- numbers the collector can vouch for: what it handed to the kernel.
    nf_records_out UInt64 DEFAULT 0,
    nf_packets_out UInt64 DEFAULT 0,
    nf_bytes_out UInt64 DEFAULT 0,
    nf_send_errs UInt64 DEFAULT 0,
    nf_dsts String DEFAULT '',
    -- Kernel drop counter of the receiver socket. Only readable when the
    -- receiver listens on this host, hence the separate observed flag: 0 drops
    -- and "cannot see the socket" are different answers.
    nf_socket_drops UInt64 DEFAULT 0,
    nf_socket_observed UInt8 DEFAULT 0,

    -- Legs the daemon actually has enabled. An undeclared stage is absent, not
    -- broken: without this a collector without NetFlow reads as 100 % loss.
    pipeline_stages Array(LowCardinality(String)) DEFAULT [],

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
    ADD COLUMN IF NOT EXISTS exclusion_rules UInt32 DEFAULT 0 AFTER flow_bytes_excluded,
    ADD COLUMN IF NOT EXISTS nic_rx_dropped UInt64 DEFAULT 0 AFTER nic_rx_bytes,
    ADD COLUMN IF NOT EXISTS nic_rx_errors UInt64 DEFAULT 0 AFTER nic_rx_dropped,
    ADD COLUMN IF NOT EXISTS nic_rx_missed UInt64 DEFAULT 0 AFTER nic_rx_errors,
    ADD COLUMN IF NOT EXISTS nic_rx_fifo_errors UInt64 DEFAULT 0 AFTER nic_rx_missed,
    ADD COLUMN IF NOT EXISTS phy_rx_packets UInt64 DEFAULT 0 AFTER nic_rx_fifo_errors,
    ADD COLUMN IF NOT EXISTS phy_rx_discards UInt64 DEFAULT 0 AFTER phy_rx_packets,
    ADD COLUMN IF NOT EXISTS phy_counter_source LowCardinality(String) DEFAULT '' AFTER phy_rx_discards,
    ADD COLUMN IF NOT EXISTS spool_corruption_frames UInt64 DEFAULT 0 AFTER drainer_progress_age_sec,
    ADD COLUMN IF NOT EXISTS spool_corruption_bytes UInt64 DEFAULT 0 AFTER spool_corruption_frames,
    ADD COLUMN IF NOT EXISTS nf_records_out UInt64 DEFAULT 0 AFTER exclusion_rules,
    ADD COLUMN IF NOT EXISTS nf_packets_out UInt64 DEFAULT 0 AFTER nf_records_out,
    ADD COLUMN IF NOT EXISTS nf_bytes_out UInt64 DEFAULT 0 AFTER nf_packets_out,
    ADD COLUMN IF NOT EXISTS nf_send_errs UInt64 DEFAULT 0 AFTER nf_bytes_out,
    ADD COLUMN IF NOT EXISTS nf_dsts String DEFAULT '' AFTER nf_send_errs,
    ADD COLUMN IF NOT EXISTS nf_socket_drops UInt64 DEFAULT 0 AFTER nf_dsts,
    ADD COLUMN IF NOT EXISTS nf_socket_observed UInt8 DEFAULT 0 AFTER nf_socket_drops,
    ADD COLUMN IF NOT EXISTS pipeline_stages Array(LowCardinality(String)) DEFAULT [] AFTER nf_socket_observed;
