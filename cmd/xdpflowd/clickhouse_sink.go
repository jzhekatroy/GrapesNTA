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

// clickhouseSink batches flow rows and INSERTs into ClickHouse asynchronously.
// If the bounded queue is full, Enqueue drops rows and increments queueDrops — flows
// may already be deleted from the BPF map by the NetFlow path; document this as CH-only loss.
type clickhouseSink struct {
	log      *slog.Logger
	conn     chdriver.Conn
	table    string // "database.table"
	clock    ExportClock
	sourceID uint32

	batchSize     int
	flushInterval time.Duration

	ch chan []flowKV

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
	clock ExportClock,
	sourceID uint32,
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
		clock:         clock,
		sourceID:      sourceID,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		ch:            make(chan []flowKV, queueSize),
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
		"exporter_source_id", sourceID,
	)
	return s, nil
}

func fixed16(addr [16]byte) []byte {
	out := make([]byte, 16)
	copy(out, addr[:])
	return out
}

func etherType(ipVersion uint8) uint32 {
	if ipVersion == 6 {
		return 0x86DD
	}
	return 0x0800
}

func (s *clickhouseSink) insertBatch(ctx context.Context, flows []flowKV, receivedAt time.Time) bool {
	if len(flows) == 0 {
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

	q := fmt.Sprintf(stmt, s.table)
	batch, err := s.conn.PrepareBatch(ctx, q)
	if err != nil {
		s.insertErrs.Add(1)
		s.log.Warn("clickhouse prepare batch", "err", err)
		return false
	}

	var zeroAddr [16]byte
	zeroFixed := fixed16(zeroAddr)
	for _, fv := range flows {
		firstWall := s.clock.monoNsToWall(fv.v.FirstSeenNs)
		err := batch.Append(
			receivedAt,
			receivedAt,
			receivedAt,
			firstWall,
			uint32(0),
			uint64(1),
			zeroFixed,
			fixed16(fv.k.SrcAddr),
			fixed16(fv.k.DstAddr),
			uint32(0),
			uint32(0),
			etherType(fv.k.IPVersion),
			uint32(fv.k.Proto),
			uint32(keyPortHost(fv.k.SrcPort)),
			uint32(keyPortHost(fv.k.DstPort)),
			fv.v.Bytes,
			fv.v.Packets,
		)
		if err != nil {
			s.insertErrs.Add(1)
			s.log.Warn("clickhouse batch append", "err", err)
			return false
		}
	}
	if err := batch.Send(); err != nil {
		s.insertErrs.Add(1)
		s.log.Warn("clickhouse batch send", "err", err)
		return false
	}
	s.batchesOK.Add(1)
	s.recordsWritten.Add(uint64(len(flows)))
	return true
}

func (s *clickhouseSink) run() {
	defer s.wg.Done()
	batch := make([]flowKV, 0, s.batchSize)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		receivedAt := time.Now().UTC()
		if s.insertBatch(context.Background(), batch, receivedAt) {
			batch = batch[:0]
		}
	}
	finalFlush := func() {
		if len(batch) == 0 {
			return
		}
		receivedAt := time.Now().UTC()
		// Close() cancels s.ctx to stop the goroutine. Use a fresh parent
		// context for the final drain so shutdown rows can still be inserted.
		if s.insertBatch(context.Background(), batch, receivedAt) {
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

// Enqueue copies flows into the sink queue (non-blocking). On overflow, increments queueDrops.
func (s *clickhouseSink) Enqueue(flows []flowKV) {
	if s == nil || len(flows) == 0 {
		return
	}
	cp := make([]flowKV, len(flows))
	copy(cp, flows)
	select {
	case s.ch <- cp:
	default:
		s.queueDrops.Add(uint64(len(cp)))
		s.log.Warn("clickhouse queue full, dropping batch", "flows", len(cp))
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
