//go:build linux

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

type clickhouseSinkConfig struct {
	RawEnabled       bool
	RawTable         string
	RawBatchSize     int
	RawQueueSize     int
	RawWriters       int
	AnswersEnabled   bool
	AnswersTable     string
	AnswersBatchSize int
	AnswersQueueSize int
	AnswersWriters   int
	FlushInterval    time.Duration
}

type dnsClickhouseSink struct {
	log *slog.Logger

	rawEnabled   bool
	rawTable     string
	rawBatchSize int
	rawCh        chan []DNSRow
	rawWriters   int

	answersEnabled   bool
	answersTable     string
	answersBatchSize int
	answersCh        chan []DNSAnswerRow
	answersWriters   int

	flushInterval time.Duration

	rawQueued      atomic.Uint64
	rawWritten     atomic.Uint64
	rawQueueDrops  atomic.Uint64
	rawInsertErrs  atomic.Uint64
	rawBatchesOK   atomic.Uint64

	answersQueued     atomic.Uint64
	answersWritten    atomic.Uint64
	answersQueueDrops atomic.Uint64
	answersInsertErrs atomic.Uint64
	answersBatchesOK  atomic.Uint64

	// Legacy aggregate counters kept for backward-compatible logs.
	recordsQueued  atomic.Uint64
	recordsWritten atomic.Uint64
	batchesOK      atomic.Uint64
	insertErrs     atomic.Uint64
	queueDrops     atomic.Uint64

	rawDropLogMu     sync.Mutex
	lastRawDropLog   time.Time
	rawDropsSinceLog atomic.Uint64

	answersDropLogMu     sync.Mutex
	lastAnswersDropLog   time.Time
	answersDropsSinceLog atomic.Uint64

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
	return &clickhouse.Options{
		Addr: []string{host},
		Auth: clickhouse.Auth{
			Database: db,
			Username: user,
			Password: pass,
		},
		DialTimeout:     10 * time.Second,
		MaxOpenConns:    5,
		ConnMaxLifetime: time.Hour,
	}, nil
}

func fixed16Row(b [16]byte) []byte {
	out := make([]byte, 16)
	copy(out, b[:])
	return out
}

func fixed16Slice(rows [][16]byte) [][]byte {
	if len(rows) == 0 {
		return nil
	}
	out := make([][]byte, len(rows))
	for i := range rows {
		out[i] = fixed16Row(rows[i])
	}
	return out
}

func validateClickHouseTable(conn chdriver.Conn, table string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := conn.Query(ctx, fmt.Sprintf("SELECT 1 FROM %s LIMIT 0", table))
	if err != nil {
		return fmt.Errorf("validate ClickHouse table %s: %w", table, err)
	}
	rows.Close()
	return nil
}

func openClickHouseConns(opts *clickhouse.Options, n int) ([]chdriver.Conn, error) {
	if n < 1 {
		n = 1
	}
	conns := make([]chdriver.Conn, 0, n)
	for i := 0; i < n; i++ {
		conn, err := clickhouse.Open(opts)
		if err != nil {
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, fmt.Errorf("clickhouse open writer %d: %w", i, err)
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func newDNSClickhouseSink(log *slog.Logger, dsn string, cfg clickhouseSinkConfig) (*dnsClickhouseSink, error) {
	cfg.AnswersTable = strings.TrimSpace(cfg.AnswersTable)
	if !cfg.RawEnabled && !cfg.AnswersEnabled {
		return nil, errors.New("at least one of raw or answers ClickHouse sinks must be enabled")
	}
	if cfg.RawEnabled && cfg.RawTable == "" {
		return nil, errors.New("ClickHouse table (-ch-table) is required when raw sink is enabled")
	}
	if cfg.AnswersEnabled && cfg.AnswersTable == "" {
		return nil, errors.New("answers table (-ch-answers-table) is required when answers sink is enabled")
	}

	opts, err := parseClickHouseDSN(dsn)
	if err != nil {
		return nil, err
	}
	validateConn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}
	if cfg.RawEnabled {
		if err := validateClickHouseTable(validateConn, cfg.RawTable); err != nil {
			_ = validateConn.Close()
			return nil, err
		}
	}
	if cfg.AnswersEnabled {
		if err := validateClickHouseTable(validateConn, cfg.AnswersTable); err != nil {
			_ = validateConn.Close()
			return nil, err
		}
	}
	_ = validateConn.Close()

	if cfg.RawBatchSize < 1 {
		cfg.RawBatchSize = 500
	}
	if cfg.AnswersBatchSize < 1 {
		cfg.AnswersBatchSize = cfg.RawBatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}
	if cfg.RawQueueSize < 1 {
		cfg.RawQueueSize = 65536
	}
	if cfg.AnswersQueueSize < 1 {
		cfg.AnswersQueueSize = 262144
	}
	if cfg.RawWriters < 1 {
		cfg.RawWriters = 1
	}
	if cfg.AnswersWriters < 1 {
		cfg.AnswersWriters = 2
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &dnsClickhouseSink{
		log:              log,
		rawEnabled:       cfg.RawEnabled,
		rawTable:         cfg.RawTable,
		rawBatchSize:     cfg.RawBatchSize,
		rawWriters:       cfg.RawWriters,
		answersEnabled:   cfg.AnswersEnabled,
		answersTable:     cfg.AnswersTable,
		answersBatchSize: cfg.AnswersBatchSize,
		answersWriters:   cfg.AnswersWriters,
		flushInterval:    cfg.FlushInterval,
		ctx:              ctx,
		cancel:           cancel,
	}
	if cfg.RawEnabled {
		s.rawCh = make(chan []DNSRow, cfg.RawQueueSize)
	}
	if cfg.AnswersEnabled {
		s.answersCh = make(chan []DNSAnswerRow, cfg.AnswersQueueSize)
	}

	if cfg.RawEnabled {
		rawConns, err := openClickHouseConns(opts, cfg.RawWriters)
		if err != nil {
			s.cancel()
			return nil, err
		}
		for _, conn := range rawConns {
			s.wg.Add(1)
			go s.runRawWriter(conn)
		}
	}
	if cfg.AnswersEnabled {
		answersConns, err := openClickHouseConns(opts, cfg.AnswersWriters)
		if err != nil {
			s.cancel()
			return nil, err
		}
		for _, conn := range answersConns {
			s.wg.Add(1)
			go s.runAnswersWriter(conn)
		}
	}

	log.Info("dnsflowd clickhouse sink enabled",
		"raw_enabled", cfg.RawEnabled,
		"raw_table", cfg.RawTable,
		"raw_batch_size", cfg.RawBatchSize,
		"raw_queue_size", cfg.RawQueueSize,
		"raw_writers", cfg.RawWriters,
		"answers_enabled", cfg.AnswersEnabled,
		"answers_table", cfg.AnswersTable,
		"answers_batch_size", cfg.AnswersBatchSize,
		"answers_queue_size", cfg.AnswersQueueSize,
		"answers_writers", cfg.AnswersWriters,
		"flush_interval", cfg.FlushInterval,
	)
	return s, nil
}

func insertDNSBatch(ctx context.Context, log *slog.Logger, conn chdriver.Conn, table string, rows []DNSRow, rawInsertErrs, legacyInsertErrs *atomic.Uint64) bool {
	if len(rows) == 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	const stmt = `INSERT INTO %s (
    ts,
    sampler_address,
    client_ip,
    server_ip,
    client_port,
    server_port,
    is_response,
    transport,
    txid,
    rcode,
    truncated,
    recursion_desired,
    recursion_available,
    query_name,
    qtype,
    qclass,
    answers_a,
    answers_aaaa,
    answers_cname,
    answer_ttls,
    answer_count,
    raw_size
)`
	q := fmt.Sprintf(stmt, table)
	batch, err := conn.PrepareBatch(ctx, q)
	if err != nil {
		rawInsertErrs.Add(1)
		legacyInsertErrs.Add(1)
		log.Warn("dnsflowd clickhouse raw prepare batch", "err", err)
		return false
	}

	for _, r := range rows {
		err := batch.Append(
			r.Ts,
			fixed16Row(r.SamplerAddress),
			fixed16Row(r.ClientIP),
			fixed16Row(r.ServerIP),
			r.ClientPort,
			r.ServerPort,
			r.IsResponse,
			r.Transport,
			r.TXID,
			r.RCode,
			r.Truncated,
			r.RecursionDesired,
			r.RecursionAvailable,
			r.QueryName,
			r.QType,
			r.QClass,
			fixed16Slice(r.AnswersA),
			fixed16Slice(r.AnswersAAAA),
			r.AnswersCNAME,
			r.AnswerTTLs,
			r.AnswerCount,
			r.RawSize,
		)
		if err != nil {
			rawInsertErrs.Add(1)
			legacyInsertErrs.Add(1)
			log.Warn("dnsflowd clickhouse raw batch append", "err", err)
			return false
		}
	}
	if err := batch.Send(); err != nil {
		rawInsertErrs.Add(1)
		legacyInsertErrs.Add(1)
		log.Warn("dnsflowd clickhouse raw batch send", "err", err)
		return false
	}
	return true
}

func insertDNSAnswersBatch(ctx context.Context, log *slog.Logger, conn chdriver.Conn, table string, rows []DNSAnswerRow, answersInsertErrs *atomic.Uint64) bool {
	if len(rows) == 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	const stmt = `INSERT INTO %s (
    ts,
    sampler_address,
    client_ip,
    server_ip,
    client_port,
    server_port,
    query_name,
    qtype,
    qclass,
    answer_type,
    answer_ip,
    ttl,
    rcode,
    txid,
    transport
)`
	q := fmt.Sprintf(stmt, table)
	batch, err := conn.PrepareBatch(ctx, q)
	if err != nil {
		answersInsertErrs.Add(1)
		log.Warn("dnsflowd clickhouse answers prepare batch", "err", err)
		return false
	}

	for _, r := range rows {
		err := batch.Append(
			r.Ts,
			fixed16Row(r.SamplerAddress),
			fixed16Row(r.ClientIP),
			fixed16Row(r.ServerIP),
			r.ClientPort,
			r.ServerPort,
			r.QueryName,
			r.QType,
			r.QClass,
			r.AnswerType,
			fixed16Row(r.AnswerIP),
			r.TTL,
			r.RCode,
			r.TXID,
			r.Transport,
		)
		if err != nil {
			answersInsertErrs.Add(1)
			log.Warn("dnsflowd clickhouse answers batch append", "err", err)
			return false
		}
	}
	if err := batch.Send(); err != nil {
		answersInsertErrs.Add(1)
		log.Warn("dnsflowd clickhouse answers batch send", "err", err)
		return false
	}
	return true
}

func (s *dnsClickhouseSink) runRawWriter(conn chdriver.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	batch := make([]DNSRow, 0, s.rawBatchSize)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if insertDNSBatch(context.Background(), s.log, conn, s.rawTable, batch, &s.rawInsertErrs, &s.insertErrs) {
			n := uint64(len(batch))
			s.rawWritten.Add(n)
			s.recordsWritten.Add(n)
			s.rawBatchesOK.Add(1)
			s.batchesOK.Add(1)
			batch = batch[:0]
		}
	}
	finalFlush := func() {
		if len(batch) == 0 {
			return
		}
		flush()
	}
	drainAndFinalFlush := func() {
		for {
			select {
			case rows := <-s.rawCh:
				batch = append(batch, rows...)
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
		case rows := <-s.rawCh:
			batch = append(batch, rows...)
			if s.ctx.Err() != nil {
				drainAndFinalFlush()
				return
			}
			if len(batch) >= s.rawBatchSize {
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

func (s *dnsClickhouseSink) runAnswersWriter(conn chdriver.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	batch := make([]DNSAnswerRow, 0, s.answersBatchSize)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if insertDNSAnswersBatch(context.Background(), s.log, conn, s.answersTable, batch, &s.answersInsertErrs) {
			n := uint64(len(batch))
			s.answersWritten.Add(n)
			s.answersBatchesOK.Add(1)
			s.batchesOK.Add(1)
			batch = batch[:0]
		}
	}
	finalFlush := func() {
		if len(batch) == 0 {
			return
		}
		flush()
	}
	drainAndFinalFlush := func() {
		for {
			select {
			case rows := <-s.answersCh:
				batch = append(batch, rows...)
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
		case rows := <-s.answersCh:
			batch = append(batch, rows...)
			if s.ctx.Err() != nil {
				drainAndFinalFlush()
				return
			}
			if len(batch) >= s.answersBatchSize {
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

func (s *dnsClickhouseSink) enqueueRaw(rows []DNSRow) {
	if s == nil || !s.rawEnabled || len(rows) == 0 || s.rawCh == nil {
		return
	}
	cp := make([]DNSRow, len(rows))
	copy(cp, rows)
	select {
	case s.rawCh <- cp:
		n := uint64(len(cp))
		s.rawQueued.Add(n)
		s.recordsQueued.Add(n)
	default:
		n := uint64(len(cp))
		s.rawQueueDrops.Add(n)
		s.queueDrops.Add(n)
		s.rawDropsSinceLog.Add(n)
		s.maybeLogRawDrops()
	}
}

func (s *dnsClickhouseSink) enqueueAnswers(rows []DNSAnswerRow) {
	if s == nil || !s.answersEnabled || len(rows) == 0 || s.answersCh == nil {
		return
	}
	cp := make([]DNSAnswerRow, len(rows))
	copy(cp, rows)
	select {
	case s.answersCh <- cp:
		s.answersQueued.Add(uint64(len(cp)))
	default:
		n := uint64(len(rows))
		s.answersQueueDrops.Add(n)
		s.queueDrops.Add(n)
		s.answersDropsSinceLog.Add(n)
		s.maybeLogAnswersDrops()
	}
}

func (s *dnsClickhouseSink) EnqueueRows(rows []DNSRow) {
	if s == nil || len(rows) == 0 {
		return
	}
	if s.rawEnabled {
		s.enqueueRaw(rows)
	}
	if s.answersEnabled {
		answers := make([]DNSAnswerRow, 0)
		for _, row := range rows {
			answers = append(answers, dnsAnswersFromRow(row)...)
		}
		if len(answers) > 0 {
			s.enqueueAnswers(answers)
		}
	}
}

func (s *dnsClickhouseSink) maybeLogRawDrops() {
	if !s.rawDropLogMu.TryLock() {
		return
	}
	defer s.rawDropLogMu.Unlock()
	now := time.Now()
	if now.Sub(s.lastRawDropLog) < time.Second {
		return
	}
	s.lastRawDropLog = now
	dropped := s.rawDropsSinceLog.Swap(0)
	if dropped == 0 {
		return
	}
	s.log.Warn("dnsflowd clickhouse raw queue full",
		"dropped_rows_last_second", dropped,
		"raw_queue_drops_total", s.rawQueueDrops.Load(),
		"raw_written_total", s.rawWritten.Load(),
	)
}

func (s *dnsClickhouseSink) maybeLogAnswersDrops() {
	if !s.answersDropLogMu.TryLock() {
		return
	}
	defer s.answersDropLogMu.Unlock()
	now := time.Now()
	if now.Sub(s.lastAnswersDropLog) < time.Second {
		return
	}
	s.lastAnswersDropLog = now
	dropped := s.answersDropsSinceLog.Swap(0)
	if dropped == 0 {
		return
	}
	s.log.Warn("dnsflowd clickhouse answers queue full",
		"dropped_rows_last_second", dropped,
		"answers_queue_drops_total", s.answersQueueDrops.Load(),
		"answers_written_total", s.answersWritten.Load(),
	)
}

func (s *dnsClickhouseSink) RawQueueDrops() uint64      { return s.rawQueueDrops.Load() }
func (s *dnsClickhouseSink) AnswersQueueDrops() uint64  { return s.answersQueueDrops.Load() }
func (s *dnsClickhouseSink) RawWriterLag() uint64 {
	q, w := s.rawQueued.Load(), s.rawWritten.Load()
	if q <= w {
		return 0
	}
	return q - w
}
func (s *dnsClickhouseSink) AnswersWriterLag() uint64 {
	q, w := s.answersQueued.Load(), s.answersWritten.Load()
	if q <= w {
		return 0
	}
	return q - w
}
func (s *dnsClickhouseSink) RawQueueDepth() int {
	if s.rawCh == nil {
		return 0
	}
	return len(s.rawCh)
}
func (s *dnsClickhouseSink) AnswersQueueDepth() int {
	if s.answersCh == nil {
		return 0
	}
	return len(s.answersCh)
}

func (s *dnsClickhouseSink) Close() {
	s.log.Info("dnsflowd clickhouse closing",
		"raw_enabled", s.rawEnabled,
		"raw_queued", s.rawQueued.Load(),
		"raw_written", s.rawWritten.Load(),
		"raw_queue_drops", s.rawQueueDrops.Load(),
		"answers_enabled", s.answersEnabled,
		"answers_queued", s.answersQueued.Load(),
		"answers_written", s.answersWritten.Load(),
		"answers_queue_drops", s.answersQueueDrops.Load(),
		"raw_insert_errs", s.rawInsertErrs.Load(),
		"answers_insert_errs", s.answersInsertErrs.Load(),
		"insert_errs", s.insertErrs.Load(),
		"queue_drops", s.queueDrops.Load(),
	)
	s.cancel()
	s.wg.Wait()
	s.log.Info("dnsflowd clickhouse closed",
		"raw_written", s.rawWritten.Load(),
		"answers_written", s.answersWritten.Load(),
		"raw_queue_drops", s.rawQueueDrops.Load(),
		"answers_queue_drops", s.answersQueueDrops.Load(),
		"raw_insert_errs", s.rawInsertErrs.Load(),
		"answers_insert_errs", s.answersInsertErrs.Load(),
		"insert_errs", s.insertErrs.Load(),
		"queue_drops", s.queueDrops.Load(),
	)
}

func (s *dnsClickhouseSink) LogMetrics() {
	s.log.Info("dnsflowd clickhouse",
		"raw_enabled", s.rawEnabled,
		"raw_queued", s.rawQueued.Load(),
		"raw_written", s.rawWritten.Load(),
		"raw_queue_drops", s.rawQueueDrops.Load(),
		"raw_queue_depth_batches", s.RawQueueDepth(),
		"raw_insert_errs", s.rawInsertErrs.Load(),
		"answers_enabled", s.answersEnabled,
		"answers_queued", s.answersQueued.Load(),
		"answers_written", s.answersWritten.Load(),
		"answers_queue_drops", s.answersQueueDrops.Load(),
		"answers_queue_depth_batches", s.AnswersQueueDepth(),
		"answers_insert_errs", s.answersInsertErrs.Load(),
		"records_queued", s.recordsQueued.Load(),
		"records_written", s.recordsWritten.Load(),
		"batches_ok", s.batchesOK.Load(),
		"insert_errs", s.insertErrs.Load(),
		"queue_drops", s.queueDrops.Load(),
	)
}
