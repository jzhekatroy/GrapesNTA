package flowingest

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const DefaultHealthTable = "default.collector_health_snapshots"

// ReceiverMetrics holds UDP/sFlow receive-side counters.
type ReceiverMetrics struct {
	Datagrams     uint64
	RecordsParsed uint64
	ParseErrors   uint64
	UDPQueueDrops uint64
}

// XDPMetrics holds BPF PERCPU stats counters.
type XDPMetrics struct {
	TotalPackets uint64
	TotalBytes   uint64
	MapFull      uint64
	ParseErrors  uint64
	NonIPPass    uint64
}

// NetFlowMetrics is the last thing the collector can vouch for on the export
// leg: UDP acknowledges nothing, so "handed to the kernel without error" is the
// end of our responsibility.
type NetFlowMetrics struct {
	RecordsOut uint64
	PacketsOut uint64
	BytesOut   uint64
	SendErrs   uint64
	Dsts       string
}

// Pipeline stage names a daemon declares. An undeclared stage is absent from
// the chain, not broken — without this a collector without a NetFlow leg reads
// as total loss on that leg.
const (
	StageInterface  = "interface"
	StageCollector  = "collector"
	StageReceiver   = "receiver"
	StageClickHouse = "clickhouse"
	StageNetFlow    = "netflow"
)

// HealthReporterConfig configures periodic INSERT into collector_health_snapshots.
type HealthReporterConfig struct {
	DSN         string
	Table       string
	CollectorID string
	SourceID    string
	Daemon      string
	Iface       string
	// Stages the daemon actually runs; see the Stage* constants.
	Stages []string
	// UDP ports of export sinks living on this host, whose kernel drop
	// counters we can read. Remote sinks are left out on purpose.
	LocalSinkPorts []uint16
	// Driver counter names for the wire-side interface numbers, in priority
	// order. Empty falls back to DefaultLinkPacketCounters /
	// DefaultLinkDiscardCounters; set them when a NIC names things unusually.
	PhyPacketCounters  []string
	PhyDiscardCounters []string
}

// HealthReporter writes cumulative health snapshots to ClickHouse.
type HealthReporter struct {
	log         *slog.Logger
	conn        chdriver.Conn
	table       string
	collectorID string
	sourceID    string
	daemon      string
	iface       string
	hostname    string
	stages      []string
	sinkPorts   []uint16
	phyPktNames []string
	phyDscNames []string

	prevPhyDiscards uint64
	havePhyBaseline bool
}

func NewHealthReporter(log *slog.Logger, cfg HealthReporterConfig) (*HealthReporter, error) {
	dsn := strings.TrimSpace(cfg.DSN)
	if dsn == "" {
		return nil, nil
	}
	table := strings.TrimSpace(cfg.Table)
	if table == "" {
		table = DefaultHealthTable
	}
	sourceID := strings.TrimSpace(cfg.SourceID)
	if sourceID == "" {
		return nil, fmt.Errorf("health reporter: source_id is required")
	}
	daemon := strings.TrimSpace(cfg.Daemon)
	if daemon == "" {
		return nil, fmt.Errorf("health reporter: daemon is required")
	}
	opts, err := ParseClickHouseDSN(dsn)
	if err != nil {
		return nil, err
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("health reporter clickhouse open: %w", err)
	}
	host, _ := os.Hostname()
	r := &HealthReporter{
		log:         log,
		conn:        conn,
		table:       table,
		collectorID: strings.TrimSpace(cfg.CollectorID),
		sourceID:    sourceID,
		daemon:      daemon,
		iface:       strings.TrimSpace(cfg.Iface),
		hostname:    host,
		stages:      append([]string(nil), cfg.Stages...),
		sinkPorts:   append([]uint16(nil), cfg.LocalSinkPorts...),
		phyPktNames: append([]string(nil), cfg.PhyPacketCounters...),
		phyDscNames: append([]string(nil), cfg.PhyDiscardCounters...),
	}
	log.Info("health reporter enabled",
		"table", table,
		"collector_id", r.collectorID,
		"source_id", sourceID,
		"daemon", daemon,
		"stages", strings.Join(r.stages, ","),
		"local_sink_ports", r.sinkPorts,
	)
	return r, nil
}

func (r *HealthReporter) Close() {
	if r == nil || r.conn == nil {
		return
	}
	_ = r.conn.Close()
}

type HealthWriteInput struct {
	XDP      XDPMetrics
	Receiver ReceiverMetrics
	CH       HealthSnapshot
	// Exclusions is what the operator rule catalog deliberately discarded.
	// Without it the XDP-vs-ClickHouse completeness ratio reads intentional
	// drops as ingest loss.
	Exclusions           ExclusionStats
	NetFlow              NetFlowMetrics
	MapFullDelta         uint64
	InsertErrsDelta      uint64
	QueueDropsDelta      uint64
	UDPQueueDropsDelta   uint64
	NFSendErrsDelta      uint64
	SpoolCorruptionDelta uint64
	// PhyRxDiscardDelta is filled by the reporter itself, which owns the
	// interface counters; callers leave it alone.
	PhyRxDiscardDelta      uint64
	LagSegmentsThreshold   int64
	WriterLagRowsThreshold uint64
	DrainerAgeThreshold    time.Duration
}

func classifyHealthStatus(in HealthWriteInput) (string, []string) {
	reasons := make([]string, 0, 4)
	status := "ok"

	add := func(level, reason string) {
		reasons = append(reasons, reason)
		if level == "critical" {
			status = "critical"
			return
		}
		if status != "critical" && level == "warning" {
			status = "warning"
		}
	}

	if in.MapFullDelta > 0 {
		add("critical", "xdp_map_full")
	}
	if in.InsertErrsDelta > 0 {
		add("critical", "clickhouse_insert_errors")
	}
	if in.QueueDropsDelta > 0 {
		add("critical", "clickhouse_queue_drops")
	}
	if in.UDPQueueDropsDelta > 0 {
		add("critical", "udp_queue_drops")
	}
	// Both are silent data loss: the export socket refused datagrams, or the
	// spool drainer skipped a frame it could not decode.
	if in.NFSendErrsDelta > 0 {
		add("critical", "netflow_send_errors")
	}
	if in.SpoolCorruptionDelta > 0 {
		add("critical", "spool_corruption")
	}
	// The port could not take the traffic in — nothing downstream can recover
	// it, and no amount of tuning inside the collector will show it.
	if in.PhyRxDiscardDelta > 0 {
		add("warning", "phy_rx_discards")
	}
	writerLag := uint64(0)
	if in.CH.RecordsQueued > in.CH.RecordsWritten {
		writerLag = in.CH.RecordsQueued - in.CH.RecordsWritten
	}
	if in.CH.RecordsSpooled > in.CH.RecordsAcked {
		writerLag = in.CH.RecordsSpooled - in.CH.RecordsAcked
	}
	if in.LagSegmentsThreshold > 0 && in.CH.LagSegments > in.LagSegmentsThreshold {
		add("warning", "spool_lag_segments")
	}
	if in.WriterLagRowsThreshold > 0 && writerLag > in.WriterLagRowsThreshold {
		add("warning", "writer_lag_rows")
	}
	if in.CH.LagSegments > 0 && in.DrainerAgeThreshold > 0 && in.CH.DrainerProgressAge > in.DrainerAgeThreshold {
		add("warning", "drainer_stalled")
	}
	if len(reasons) == 0 {
		return "ok", reasons
	}
	return status, reasons
}

func (r *HealthReporter) Write(ctx context.Context, in HealthWriteInput) error {
	if r == nil {
		return nil
	}
	nic := ReadNICStats(r.iface)
	link := ReadLinkStats(r.iface, r.phyPktNames, r.phyDscNames)
	sinkDrops, sinkObserved := ReadUDPSocketDrops(r.sinkPorts)

	// First tick only establishes the baseline: a counter that has been
	// growing since boot must not report the whole history as a fresh loss.
	if link.Source != "" {
		if r.havePhyBaseline && link.RxDiscards > r.prevPhyDiscards {
			in.PhyRxDiscardDelta = link.RxDiscards - r.prevPhyDiscards
		}
		r.prevPhyDiscards = link.RxDiscards
		r.havePhyBaseline = true
	}
	status, reasons := classifyHealthStatus(in)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	const stmt = `INSERT INTO %s (
    ts,
    collector_id,
    source_id,
    daemon,
    hostname,
    iface,
    xdp_total_packets,
    xdp_total_bytes,
    xdp_map_full,
    xdp_parse_errors,
    xdp_non_ip_pass,
    nic_rx_packets,
    nic_rx_bytes,
    nic_rx_dropped,
    nic_rx_errors,
    nic_rx_missed,
    nic_rx_fifo_errors,
    phy_rx_packets,
    phy_rx_discards,
    phy_counter_source,
    datagrams,
    records_parsed,
    receiver_parse_errors,
    udp_queue_drops,
    ch_mode,
    records_queued,
    records_written,
    records_spooled,
    records_acked,
    flow_packets_queued,
    flow_bytes_queued,
    flow_packets_written,
    flow_bytes_written,
    flow_packets_spooled,
    flow_bytes_spooled,
    flow_packets_acked,
    flow_bytes_acked,
    insert_errs,
    ch_queue_drops,
    lag_segments,
    drainer_progress_age_sec,
    spool_corruption_frames,
    spool_corruption_bytes,
    flow_rows_excluded,
    flow_packets_excluded,
    flow_bytes_excluded,
    exclusion_rules,
    nf_records_out,
    nf_packets_out,
    nf_bytes_out,
    nf_send_errs,
    nf_dsts,
    nf_socket_drops,
    nf_socket_observed,
    pipeline_stages,
    status,
    status_reasons
)`

	q := fmt.Sprintf(stmt, r.table)
	batch, err := r.conn.PrepareBatch(ctx, q)
	if err != nil {
		r.log.Warn("health snapshot prepare batch", "err", err)
		return err
	}
	err = batch.Append(
		time.Now().UTC(),
		r.collectorID,
		r.sourceID,
		r.daemon,
		r.hostname,
		r.iface,
		in.XDP.TotalPackets,
		in.XDP.TotalBytes,
		in.XDP.MapFull,
		in.XDP.ParseErrors,
		in.XDP.NonIPPass,
		nic.RxPackets,
		nic.RxBytes,
		nic.RxDropped,
		nic.RxErrors,
		nic.RxMissed,
		nic.RxFifo,
		link.RxPackets,
		link.RxDiscards,
		link.Source,
		in.Receiver.Datagrams,
		in.Receiver.RecordsParsed,
		in.Receiver.ParseErrors,
		in.Receiver.UDPQueueDrops,
		in.CH.Mode,
		in.CH.RecordsQueued,
		in.CH.RecordsWritten,
		in.CH.RecordsSpooled,
		in.CH.RecordsAcked,
		in.CH.FlowPacketsQueued,
		in.CH.FlowBytesQueued,
		in.CH.FlowPacketsWritten,
		in.CH.FlowBytesWritten,
		in.CH.FlowPacketsSpooled,
		in.CH.FlowBytesSpooled,
		in.CH.FlowPacketsAcked,
		in.CH.FlowBytesAcked,
		in.CH.InsertErrs,
		in.CH.QueueDrops,
		in.CH.LagSegments,
		in.CH.DrainerProgressAge.Seconds(),
		in.CH.CorruptionFrames,
		in.CH.CorruptionBytes,
		in.Exclusions.Rows,
		in.Exclusions.Packets,
		in.Exclusions.Bytes,
		uint32(in.Exclusions.Rules),
		in.NetFlow.RecordsOut,
		in.NetFlow.PacketsOut,
		in.NetFlow.BytesOut,
		in.NetFlow.SendErrs,
		in.NetFlow.Dsts,
		sinkDrops,
		boolToUInt8(sinkObserved),
		r.stages,
		status,
		reasons,
	)
	if err != nil {
		r.log.Warn("health snapshot batch append", "err", err)
		return err
	}
	if err := batch.Send(); err != nil {
		r.log.Warn("health snapshot insert failed", "err", err)
		return err
	}
	r.log.Info("health snapshot",
		"source_id", r.sourceID,
		"status", status,
		"xdp_total_packets", in.XDP.TotalPackets,
		"xdp_total_bytes", in.XDP.TotalBytes,
		"xdp_map_full", in.XDP.MapFull,
		"records_written", in.CH.RecordsWritten,
		"records_acked", in.CH.RecordsAcked,
		"flow_packets_acked", in.CH.FlowPacketsAcked,
		"flow_bytes_acked", in.CH.FlowBytesAcked,
		"insert_errs", in.CH.InsertErrs,
		"ch_queue_drops", in.CH.QueueDrops,
		"flow_rows_excluded", in.Exclusions.Rows,
		"flow_packets_excluded", in.Exclusions.Packets,
		"exclusion_rules", in.Exclusions.Rules,
		"nic_rx_dropped", nic.RxDropped,
		"nic_rx_fifo_errors", nic.RxFifo,
		"phy_rx_packets", link.RxPackets,
		"phy_rx_discards", link.RxDiscards,
		"phy_counter_source", link.Source,
		"nf_packets_out", in.NetFlow.PacketsOut,
		"nf_send_errs", in.NetFlow.SendErrs,
		"nf_socket_drops", sinkDrops,
		"nf_socket_observed", sinkObserved,
		"spool_corruption_frames", in.CH.CorruptionFrames,
	)
	return nil
}

func boolToUInt8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
