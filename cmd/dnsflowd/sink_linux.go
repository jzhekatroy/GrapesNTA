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

type dnsClickhouseSink struct {
	log           *slog.Logger
	conn          chdriver.Conn
	table         string
	batchSize     int
	flushInterval time.Duration
	ch            chan []DNSRow

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

func newDNSClickhouseSink(
	log *slog.Logger,
	dsn, table string,
	batchSize int,
	flushInterval time.Duration,
	queueSize int,
) (*dnsClickhouseSink, error) {
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
	s := &dnsClickhouseSink{
		log:           log,
		conn:          conn,
		table:         table,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		ch:            make(chan []DNSRow, queueSize),
		ctx:           ctx,
		cancel:        cancel,
	}
	s.wg.Add(1)
	go s.run()
	log.Info("dnsflowd clickhouse sink enabled",
		"table", table,
		"batch_size", batchSize,
		"flush_interval", flushInterval,
		"queue_size", queueSize,
	)
	return s, nil
}

func insertDNSBatch(ctx context.Context, log *slog.Logger, conn chdriver.Conn, table string, rows []DNSRow, insertErrs *atomic.Uint64) bool {
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
		insertErrs.Add(1)
		log.Warn("dnsflowd clickhouse prepare batch", "err", err)
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
			insertErrs.Add(1)
			log.Warn("dnsflowd clickhouse batch append", "err", err)
			return false
		}
	}
	if err := batch.Send(); err != nil {
		insertErrs.Add(1)
		log.Warn("dnsflowd clickhouse batch send", "err", err)
		return false
	}
	return true
}

func (s *dnsClickhouseSink) insertBatch(ctx context.Context, rows []DNSRow) bool {
	if len(rows) == 0 {
		return true
	}
	if insertDNSBatch(ctx, s.log, s.conn, s.table, rows, &s.insertErrs) {
		s.batchesOK.Add(1)
		s.recordsWritten.Add(uint64(len(rows)))
		return true
	}
	return false
}

func (s *dnsClickhouseSink) run() {
	defer s.wg.Done()
	batch := make([]DNSRow, 0, s.batchSize)
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
			case rows := <-s.ch:
				batch = append(batch, rows...)
				s.recordsQueued.Add(uint64(len(rows)))
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
		case rows := <-s.ch:
			batch = append(batch, rows...)
			s.recordsQueued.Add(uint64(len(rows)))
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

func (s *dnsClickhouseSink) EnqueueRows(rows []DNSRow) {
	if s == nil || len(rows) == 0 {
		return
	}
	cp := make([]DNSRow, len(rows))
	copy(cp, rows)
	select {
	case s.ch <- cp:
	default:
		s.queueDrops.Add(uint64(len(cp)))
		s.log.Warn("dnsflowd clickhouse queue full, dropping batch", "rows", len(cp))
	}
}

func (s *dnsClickhouseSink) Close() {
	s.log.Info("dnsflowd clickhouse closing",
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
	s.log.Info("dnsflowd clickhouse closed",
		"records_queued", s.recordsQueued.Load(),
		"records_written", s.recordsWritten.Load(),
		"batches_ok", s.batchesOK.Load(),
		"insert_errs", s.insertErrs.Load(),
		"queue_drops", s.queueDrops.Load(),
	)
}

func (s *dnsClickhouseSink) LogMetrics() {
	s.log.Info("dnsflowd clickhouse",
		"records_queued", s.recordsQueued.Load(),
		"records_written", s.recordsWritten.Load(),
		"batches_ok", s.batchesOK.Load(),
		"insert_errs", s.insertErrs.Load(),
		"queue_drops", s.queueDrops.Load(),
	)
}
