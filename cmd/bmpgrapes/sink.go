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

type clickhouseSink struct {
	log              *slog.Logger
	conn             chdriver.Conn
	eventsTable      string
	peersTable       string
	batchSize        int
	flushInterval    time.Duration
	eventsCh         chan []RouteEventRow
	peersCh          chan []PeerRow

	eventsQueued atomic.Uint64
	eventsWritten atomic.Uint64
	peersQueued  atomic.Uint64
	peersWritten atomic.Uint64
	insertErrs   atomic.Uint64
	queueDrops   atomic.Uint64

	dropLogMu sync.Mutex
	lastDropLog time.Time
	dropsSinceLog atomic.Uint64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func parseDSN(dsn string) (*clickhouse.Options, error) {
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

func fixed16(b [16]byte) []byte {
	out := make([]byte, 16)
	copy(out, b[:])
	return out
}

func newClickhouseSink(
	log *slog.Logger,
	dsn, eventsTable, peersTable string,
	batchSize int,
	flushInterval time.Duration,
	queueSize int,
) (*clickhouseSink, error) {
	if eventsTable == "" || peersTable == "" {
		return nil, errors.New("events and peers tables are required")
	}
	opts, err := parseDSN(dsn)
	if err != nil {
		return nil, err
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}
	if batchSize < 1 {
		batchSize = 500
	}
	if flushInterval <= 0 {
		flushInterval = time.Second
	}
	if queueSize < 1 {
		queueSize = 64
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &clickhouseSink{
		log:           log,
		conn:          conn,
		eventsTable:   eventsTable,
		peersTable:    peersTable,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		eventsCh:      make(chan []RouteEventRow, queueSize),
		peersCh:       make(chan []PeerRow, queueSize),
		ctx:           ctx,
		cancel:        cancel,
	}
	s.wg.Add(2)
	go s.runEvents()
	go s.runPeers()
	log.Info("bmpgrapes clickhouse sink enabled",
		"events_table", eventsTable,
		"peers_table", peersTable,
		"batch_size", batchSize,
		"flush_interval", flushInterval,
		"queue_size", queueSize,
	)
	return s, nil
}

func (s *clickhouseSink) insertEventsBatch(ctx context.Context, rows []RouteEventRow) bool {
	if len(rows) == 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	q := fmt.Sprintf(`INSERT INTO %s (
		ts, router_addr, peer_addr, peer_asn, event_type, family,
		prefix, prefix_len, next_hop, origin_asn, as_path, med, local_pref
	)`, s.eventsTable)
	batch, err := s.conn.PrepareBatch(ctx, q)
	if err != nil {
		s.insertErrs.Add(1)
		s.log.Warn("bmpgrapes events prepare batch", "err", err)
		return false
	}
	for _, r := range rows {
		err := batch.Append(
			r.Ts,
			fixed16(r.RouterAddr),
			fixed16(r.PeerAddr),
			r.PeerASN,
			r.EventType,
			r.Family,
			fixed16(r.Prefix),
			r.PrefixLen,
			fixed16(r.NextHop),
			r.OriginASN,
			r.ASPath,
			r.MED,
			r.LocalPref,
		)
		if err != nil {
			s.insertErrs.Add(1)
			s.log.Warn("bmpgrapes events append", "err", err)
			return false
		}
	}
	if err := batch.Send(); err != nil {
		s.insertErrs.Add(1)
		s.log.Warn("bmpgrapes events send", "err", err)
		return false
	}
	s.eventsWritten.Add(uint64(len(rows)))
	return true
}

func (s *clickhouseSink) insertPeersBatch(ctx context.Context, rows []PeerRow) bool {
	if len(rows) == 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	q := fmt.Sprintf(`INSERT INTO %s (
		ts, router_addr, peer_addr, peer_asn, peer_type, is_ipv6,
		state, reason, local_asn, local_addr, hold_time, negotiated_hold_time, bgp_id
	)`, s.peersTable)
	batch, err := s.conn.PrepareBatch(ctx, q)
	if err != nil {
		s.insertErrs.Add(1)
		s.log.Warn("bmpgrapes peers prepare batch", "err", err)
		return false
	}
	for _, r := range rows {
		err := batch.Append(
			r.Ts,
			fixed16(r.RouterAddr),
			fixed16(r.PeerAddr),
			r.PeerASN,
			r.PeerType,
			r.IsIPv6,
			r.State,
			r.Reason,
			r.LocalASN,
			fixed16(r.LocalAddr),
			r.HoldTime,
			r.NegotiatedHoldTime,
			r.BGPID,
		)
		if err != nil {
			s.insertErrs.Add(1)
			s.log.Warn("bmpgrapes peers append", "err", err)
			return false
		}
	}
	if err := batch.Send(); err != nil {
		s.insertErrs.Add(1)
		s.log.Warn("bmpgrapes peers send", "err", err)
		return false
	}
	s.peersWritten.Add(uint64(len(rows)))
	return true
}

func (s *clickhouseSink) runEvents() {
	defer s.wg.Done()
	batch := make([]RouteEventRow, 0, s.batchSize)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if s.insertEventsBatch(context.Background(), batch) {
			batch = batch[:0]
		}
	}
	drain := func() {
		for {
			select {
			case rows := <-s.eventsCh:
				batch = append(batch, rows...)
				s.eventsQueued.Add(uint64(len(rows)))
			default:
				flush()
				return
			}
		}
	}
	for {
		select {
		case <-s.ctx.Done():
			drain()
			return
		case rows := <-s.eventsCh:
			batch = append(batch, rows...)
			s.eventsQueued.Add(uint64(len(rows)))
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *clickhouseSink) runPeers() {
	defer s.wg.Done()
	batch := make([]PeerRow, 0, s.batchSize)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if s.insertPeersBatch(context.Background(), batch) {
			batch = batch[:0]
		}
	}
	drain := func() {
		for {
			select {
			case rows := <-s.peersCh:
				batch = append(batch, rows...)
				s.peersQueued.Add(uint64(len(rows)))
			default:
				flush()
				return
			}
		}
	}
	for {
		select {
		case <-s.ctx.Done():
			drain()
			return
		case rows := <-s.peersCh:
			batch = append(batch, rows...)
			s.peersQueued.Add(uint64(len(rows)))
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *clickhouseSink) EnqueueEvents(rows []RouteEventRow) {
	if s == nil || len(rows) == 0 {
		return
	}
	cp := make([]RouteEventRow, len(rows))
	copy(cp, rows)
	select {
	case s.eventsCh <- cp:
	default:
		s.queueDrops.Add(uint64(len(cp)))
		s.dropsSinceLog.Add(uint64(len(cp)))
		s.maybeLogDrops()
	}
}

func (s *clickhouseSink) EnqueuePeers(rows []PeerRow) {
	if s == nil || len(rows) == 0 {
		return
	}
	cp := make([]PeerRow, len(rows))
	copy(cp, rows)
	select {
	case s.peersCh <- cp:
	default:
		s.queueDrops.Add(uint64(len(cp)))
		s.dropsSinceLog.Add(uint64(len(cp)))
		s.maybeLogDrops()
	}
}

func (s *clickhouseSink) maybeLogDrops() {
	if !s.dropLogMu.TryLock() {
		return
	}
	defer s.dropLogMu.Unlock()
	now := time.Now()
	if now.Sub(s.lastDropLog) < time.Second {
		return
	}
	s.lastDropLog = now
	dropped := s.dropsSinceLog.Swap(0)
	if dropped == 0 {
		return
	}
	s.log.Warn("bmpgrapes clickhouse queue full",
		"dropped_rows_last_second", dropped,
		"queue_drops_total", s.queueDrops.Load(),
		"events_written_total", s.eventsWritten.Load(),
		"peers_written_total", s.peersWritten.Load(),
	)
}

func (s *clickhouseSink) Close() {
	s.log.Info("bmpgrapes clickhouse closing",
		"events_queued", s.eventsQueued.Load(),
		"events_written", s.eventsWritten.Load(),
		"peers_queued", s.peersQueued.Load(),
		"peers_written", s.peersWritten.Load(),
		"insert_errs", s.insertErrs.Load(),
		"queue_drops", s.queueDrops.Load(),
	)
	s.cancel()
	s.wg.Wait()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.log.Info("bmpgrapes clickhouse closed")
}

func (s *clickhouseSink) LogMetrics() {
	s.log.Info("bmpgrapes clickhouse",
		"events_queued", s.eventsQueued.Load(),
		"events_written", s.eventsWritten.Load(),
		"peers_queued", s.peersQueued.Load(),
		"peers_written", s.peersWritten.Load(),
		"insert_errs", s.insertErrs.Load(),
		"queue_drops", s.queueDrops.Load(),
	)
}
