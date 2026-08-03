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
	Datagrams      uint64
	RecordsParsed  uint64
	ParseErrors    uint64
	UDPQueueDrops  uint64
}

// XDPMetrics holds BPF PERCPU stats counters.
type XDPMetrics struct {
	TotalPackets uint64
	TotalBytes   uint64
	MapFull      uint64
	ParseErrors  uint64
	NonIPPass    uint64
}

// HealthReporterConfig configures periodic INSERT into collector_health_snapshots.
type HealthReporterConfig struct {
	DSN         string
	Table       string
	CollectorID string
	SourceID    string
	Daemon      string
	Iface       string
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
	}
	log.Info("health reporter enabled",
		"table", table,
		"collector_id", r.collectorID,
		"source_id", sourceID,
		"daemon", daemon,
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
	XDP                    XDPMetrics
	Receiver               ReceiverMetrics
	CH                     HealthSnapshot
	// Exclusions is what the operator rule catalog deliberately discarded.
	// Without it the XDP-vs-ClickHouse completeness ratio reads intentional
	// drops as ingest loss.
	Exclusions             ExclusionStats
	MapFullDelta           uint64
	InsertErrsDelta        uint64
	QueueDropsDelta        uint64
	UDPQueueDropsDelta     uint64
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
	nicRxPkts, nicRxBytes := ReadNICStats(r.iface)
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
    flow_rows_excluded,
    flow_packets_excluded,
    flow_bytes_excluded,
    exclusion_rules,
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
		nicRxPkts,
		nicRxBytes,
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
		in.Exclusions.Rows,
		in.Exclusions.Packets,
		in.Exclusions.Bytes,
		uint32(in.Exclusions.Rules),
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
	)
	return nil
}
