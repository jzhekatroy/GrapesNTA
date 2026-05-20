package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// clickhouseSink batches FlowRow and INSERTs into ClickHouse asynchronously.
// If the bounded queue is full, EnqueueRows drops rows and increments queueDrops — flows
// may already be deleted from the BPF map by the NetFlow path; document this as CH-only loss.
type clickhouseSink struct {
	log   *slog.Logger
	conn  chdriver.Conn
	table string // "database.table"

	batchSize     int
	flushInterval time.Duration

	ch chan []FlowRow

	recordsQueued  atomic.Uint64
	recordsWritten atomic.Uint64
	batchesOK      atomic.Uint64
	insertErrs     atomic.Uint64
	queueDrops     atomic.Uint64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func parseClickHouseDSN(dsn string) (*clickhouse.Options, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, errors.New("empty DSN")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse DSN: %w", err)
	}
	if u.Scheme != "clickhouse" && u.Scheme != "clickhouses" {
		return nil, fmt.Errorf("DSN scheme must be clickhouse:// (got %q)", u.Scheme)
	}
	host := u.Host
	if host == "" {
		return nil, errors.New("DSN missing host")
	}
	db := strings.TrimPrefix(u.Path, "/")
	if db == "" {
		db = "default"
	}
	user := "default"
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	opts := &clickhouse.Options{
		Addr: []string{host},
		Auth: clickhouse.Auth{
			Database: db,
			Username: user,
			Password: pass,
		},
		DialTimeout:     10 * time.Second,
		MaxOpenConns:    5,
		ConnMaxLifetime: time.Hour,
	}
	return opts, nil
}

func newClickhouseSink(
	log *slog.Logger,
	dsn, table string,
	batchSize int,
	flushInterval time.Duration,
	queueSize int,
) (*clickhouseSink, error) {
	if table == "" {
		return nil, errors.New("ClickHouse table (-ch-table) is required when -ch-dsn is set")
	}
	opts, err := parseClickHouseDSN(dsn)
	if err != nil {
		return nil, err
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if batchSize < 1 {
		batchSize = 500
	}
	if flushInterval <= 0 {
		flushInterval = time.Second
	}
	if queueSize < 1 {
		queueSize = 64
	}
	s := &clickhouseSink{
		log:           log,
		conn:          conn,
		table:         table,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		ch:            make(chan []FlowRow, queueSize),
		ctx:           ctx,
		cancel:        cancel,
	}
	s.wg.Add(1)
	go s.run()
	log.Info("clickhouse sink enabled",
		"table", table,
		"batch_size", batchSize,
		"flush_interval", flushInterval,
		"queue_size", queueSize,
	)
	return s, nil
}

func etherType(ipVersion uint8) uint32 {
	if ipVersion == 6 {
		return 0x86DD
	}
	return 0x0800
}

// insertBatchRows executes a single INSERT. insertErrs is incremented on failure.
func insertBatchRows(ctx context.Context, log *slog.Logger, conn chdriver.Conn, table string, rows []FlowRow, insertErrs *atomic.Uint64) bool {
	if len(rows) == 0 {
		return true
	}
	if !rowsHaveEnrichment(rows) {
		return insertCompactBatchRows(ctx, log, conn, table, rows, insertErrs)
	}
	return insertEnrichedBatchRows(ctx, log, conn, table, rows, insertErrs)
}

func insertCompactBatchRows(ctx context.Context, log *slog.Logger, conn chdriver.Conn, table string, rows []FlowRow, insertErrs *atomic.Uint64) bool {
	if len(rows) == 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	const stmt = `INSERT INTO %s (
    date,
    time_inserted_ns,
    time_received_ns,
    time_flow_start_ns,
    sequence_num,
    sampling_rate,
    sampler_address,
    src_addr,
    dst_addr,
    src_as,
    dst_as,
    etype,
    proto,
    src_port,
    dst_port,
    bytes,
    packets
)`

	q := fmt.Sprintf(stmt, table)
	batch, err := conn.PrepareBatch(ctx, q)
	if err != nil {
		insertErrs.Add(1)
		log.Warn("clickhouse prepare batch", "err", err)
		return false
	}

	// Iterate by index + pointer to avoid per-row copies of the ~200B FlowRow
	// struct and to let r.*Addr[:] reference the existing backing array (no
	// per-row 16-byte heap allocation as in the previous fixed16 helper).
	// The driver consumes the staged values during batch.Send() below, so
	// these slices outlive their use.
	for i := range rows {
		r := &rows[i]
		err := batch.Append(
			r.Date,
			r.TimeInsertedNs,
			r.TimeReceivedNs,
			r.TimeFlowStartNs,
			r.SequenceNum,
			r.SamplingRate,
			r.SamplerAddress[:],
			r.SrcAddr[:],
			r.DstAddr[:],
			r.SrcAS,
			r.DstAS,
			r.Etype,
			r.Proto,
			r.SrcPort,
			r.DstPort,
			r.Bytes,
			r.Packets,
		)
		if err != nil {
			insertErrs.Add(1)
			log.Warn("clickhouse batch append", "err", err)
			return false
		}
	}
	if err := batch.Send(); err != nil {
		insertErrs.Add(1)
		log.Warn("clickhouse batch send", "err", err)
		return false
	}
	return true
}

func insertEnrichedBatchRows(ctx context.Context, log *slog.Logger, conn chdriver.Conn, table string, rows []FlowRow, insertErrs *atomic.Uint64) bool {
	if len(rows) == 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	const stmt = `INSERT INTO %s (
    date,
    time_inserted_ns,
    time_received_ns,
    time_flow_start_ns,
    sequence_num,
    sampling_rate,
    sampler_address,
    src_addr,
    dst_addr,
    src_as,
    dst_as,
    src_asn,
    dst_asn,
    direction,
    src_kind,
    dst_kind,
    src_label,
    dst_label,
    src_operator,
    dst_operator,
    src_attachment_kind,
    dst_attachment_kind,
    src_attachment_boundary,
    dst_attachment_boundary,
    src_attachment_label,
    dst_attachment_label,
    src_attachment_operator,
    dst_attachment_operator,
    src_endpoint_scope,
    dst_endpoint_scope,
    src_endpoint_source,
    dst_endpoint_source,
    src_network_name,
    dst_network_name,
    src_network_role,
    dst_network_role,
    src_vlan,
    dst_vlan,
    etype,
    proto,
    src_port,
    dst_port,
    bytes,
    packets
)`

	q := fmt.Sprintf(stmt, table)
	batch, err := conn.PrepareBatch(ctx, q)
	if err != nil {
		insertErrs.Add(1)
		log.Warn("clickhouse prepare batch", "err", err)
		return false
	}

	for i := range rows {
		r := &rows[i]
		flowRowApplyInsertDefaults(r)
		err := batch.Append(
			r.Date,
			r.TimeInsertedNs,
			r.TimeReceivedNs,
			r.TimeFlowStartNs,
			r.SequenceNum,
			r.SamplingRate,
			r.SamplerAddress[:],
			r.SrcAddr[:],
			r.DstAddr[:],
			r.SrcAS,
			r.DstAS,
			r.SrcASN,
			r.DstASN,
			r.Direction,
			r.SrcKind,
			r.DstKind,
			r.SrcLabel,
			r.DstLabel,
			r.SrcOperator,
			r.DstOperator,
			r.SrcAttachmentKind,
			r.DstAttachmentKind,
			r.SrcAttachmentBoundary,
			r.DstAttachmentBoundary,
			r.SrcAttachmentLabel,
			r.DstAttachmentLabel,
			r.SrcAttachmentOperator,
			r.DstAttachmentOperator,
			r.SrcEndpointScope,
			r.DstEndpointScope,
			r.SrcEndpointSource,
			r.DstEndpointSource,
			r.SrcNetworkName,
			r.DstNetworkName,
			r.SrcNetworkRole,
			r.DstNetworkRole,
			r.SrcVLAN,
			r.DstVLAN,
			r.Etype,
			r.Proto,
			r.SrcPort,
			r.DstPort,
			r.Bytes,
			r.Packets,
		)
		if err != nil {
			insertErrs.Add(1)
			log.Warn("clickhouse batch append", "err", err)
			return false
		}
	}
	if err := batch.Send(); err != nil {
		insertErrs.Add(1)
		log.Warn("clickhouse batch send", "err", err)
		return false
	}
	return true
}

func rowsHaveEnrichment(rows []FlowRow) bool {
	for i := range rows {
		r := &rows[i]
		if r.SrcASN != 0 || r.DstASN != 0 ||
			r.Direction != "" || r.SrcKind != "" || r.DstKind != "" ||
			r.SrcLabel != "" || r.DstLabel != "" ||
			r.SrcOperator != "" || r.DstOperator != "" ||
			r.SrcAttachmentKind != "" || r.DstAttachmentKind != "" ||
			r.SrcEndpointScope != "" || r.DstEndpointScope != "" ||
			r.SrcEndpointSource != "" || r.DstEndpointSource != "" ||
			r.SrcNetworkName != "" || r.DstNetworkName != "" ||
			r.SrcVLAN != 0 || r.DstVLAN != 0 {
			return true
		}
	}
	return false
}

// flowRowApplyInsertDefaults fills enrichment columns in-place. Operating on a
// pointer avoids copying the ~200-byte FlowRow struct once per row in the hot
// INSERT loop.
func flowRowApplyInsertDefaults(r *FlowRow) {
	if r.Direction == "" {
		r.Direction = "unknown"
	}
	if r.SrcKind == "" {
		r.SrcKind = "unknown"
	}
	if r.DstKind == "" {
		r.DstKind = "unknown"
	}
	if r.SrcEndpointScope == "" {
		r.SrcEndpointScope = r.SrcKind
	}
	if r.DstEndpointScope == "" {
		r.DstEndpointScope = r.DstKind
	}
	if r.SrcEndpointScope == "" {
		r.SrcEndpointScope = "unknown"
	}
	if r.DstEndpointScope == "" {
		r.DstEndpointScope = "unknown"
	}
	if r.SrcEndpointSource == "" {
		r.SrcEndpointSource = "unknown"
	}
	if r.DstEndpointSource == "" {
		r.DstEndpointSource = "unknown"
	}
	if r.SrcAttachmentKind == "" {
		r.SrcAttachmentKind = "unknown"
	}
	if r.DstAttachmentKind == "" {
		r.DstAttachmentKind = "unknown"
	}
	if r.SrcAttachmentBoundary == "" {
		r.SrcAttachmentBoundary = "unknown"
	}
	if r.DstAttachmentBoundary == "" {
		r.DstAttachmentBoundary = "unknown"
	}
	if r.SrcASN == 0 && r.SrcAS != 0 {
		r.SrcASN = r.SrcAS
	}
	if r.DstASN == 0 && r.DstAS != 0 {
		r.DstASN = r.DstAS
	}
}

func (s *clickhouseSink) insertBatch(ctx context.Context, rows []FlowRow) bool {
	if len(rows) == 0 {
		return true
	}
	if insertBatchRows(ctx, s.log, s.conn, s.table, rows, &s.insertErrs) {
		s.batchesOK.Add(1)
		s.recordsWritten.Add(uint64(len(rows)))
		return true
	}
	return false
}

func (s *clickhouseSink) run() {
	defer s.wg.Done()
	batch := make([]FlowRow, 0, s.batchSize)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if s.insertBatch(context.Background(), batch) {
			batch = batch[:0]
		}
	}
	finalFlush := func() {
		if len(batch) == 0 {
			return
		}
		if s.insertBatch(context.Background(), batch) {
			batch = batch[:0]
		}
	}
	drainAndFinalFlush := func() {
		for {
			select {
			case flows := <-s.ch:
				batch = append(batch, flows...)
				s.recordsQueued.Add(uint64(len(flows)))
			default:
				finalFlush()
				return
			}
		}
	}

	for {
		select {
		case <-s.ctx.Done():
			drainAndFinalFlush()
			return
		case flows := <-s.ch:
			batch = append(batch, flows...)
			s.recordsQueued.Add(uint64(len(flows)))
			if s.ctx.Err() != nil {
				drainAndFinalFlush()
				return
			}
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			if s.ctx.Err() != nil {
				drainAndFinalFlush()
				return
			}
			flush()
		}
	}
}

// EnqueueRows copies rows into the sink queue (non-blocking). On overflow, increments queueDrops.
func (s *clickhouseSink) EnqueueRows(rows []FlowRow) {
	if s == nil || len(rows) == 0 {
		return
	}
	cp := make([]FlowRow, len(rows))
	copy(cp, rows)
	select {
	case s.ch <- cp:
	default:
		s.queueDrops.Add(uint64(len(cp)))
		s.log.Warn("clickhouse queue full, dropping batch", "rows", len(cp))
	}
}

func (s *clickhouseSink) Close() {
	s.log.Info("clickhouse closing",
		"records_queued", s.recordsQueued.Load(),
		"records_written", s.recordsWritten.Load(),
		"insert_errs", s.insertErrs.Load(),
		"queue_drops", s.queueDrops.Load(),
	)
	s.cancel()
	s.wg.Wait()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.log.Info("clickhouse closed",
		"records_queued", s.recordsQueued.Load(),
		"records_written", s.recordsWritten.Load(),
		"batches_ok", s.batchesOK.Load(),
		"insert_errs", s.insertErrs.Load(),
		"queue_drops", s.queueDrops.Load(),
	)
}

func (s *clickhouseSink) LogMetrics() {
	s.log.Info("clickhouse",
		"records_queued", s.recordsQueued.Load(),
		"records_written", s.recordsWritten.Load(),
		"batches_ok", s.batchesOK.Load(),
		"insert_errs", s.insertErrs.Load(),
		"queue_drops", s.queueDrops.Load(),
	)
}
