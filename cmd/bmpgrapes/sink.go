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

// queueMode controls overflow behaviour of the bounded queues feeding
// ClickHouse. "block" propagates back-pressure to BMP TCP reads (no data loss,
// router slows down). "drop" silently discards rows when the queue is full.
type queueMode int

const (
	queueModeBlock queueMode = iota
	queueModeDrop
)

func parseQueueMode(s string) (queueMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "block":
		return queueModeBlock, nil
	case "drop":
		return queueModeDrop, nil
	default:
		return queueModeBlock, fmt.Errorf("unknown queue mode %q (want block | drop)", s)
	}
}

func (m queueMode) String() string {
	if m == queueModeDrop {
		return "drop"
	}
	return "block"
}

type clickhouseSink struct {
	log           *slog.Logger
	conn          chdriver.Conn
	eventsTable   string
	peersTable    string
	batchSize     int
	flushInterval time.Duration
	mode          queueMode
	eventsCh      chan []RouteEventRow
	peersCh       chan []PeerRow

	eventsQueued  atomic.Uint64
	eventsWritten atomic.Uint64
	peersQueued   atomic.Uint64
	peersWritten  atomic.Uint64
	insertErrs    atomic.Uint64
	queueDrops    atomic.Uint64
	queueBlocks   atomic.Uint64

	dropLogMu     sync.Mutex
	lastDropLog   time.Time
	dropsSinceLog atomic.Uint64

	blockLogMu     sync.Mutex
	lastBlockLog   time.Time
	blocksSinceLog atomic.Uint64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type clickhouseHealthSnapshot struct {
	EventsQueued  uint64
	EventsWritten uint64
	PeersQueued   uint64
	PeersWritten  uint64
	InsertErrs    uint64
	QueueDrops    uint64
	QueueBlocks   uint64
	EventsLagRows uint64
	PeersLagRows  uint64
	EventsQueue   int
	PeersQueue    int
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
	mode queueMode,
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
		mode:          mode,
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
		"queue_mode", mode.String(),
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

// EnqueueEvents publishes a batch of route events to the sink queue.
//
// In "block" mode (default) the call blocks until there is capacity in the
// queue, the caller's ctx is cancelled, or the sink itself is shutting down.
// This is what propagates TCP back-pressure to the BMP router and avoids
// data loss when ClickHouse temporarily slows down. In "drop" mode the call
// never blocks: if the queue is full, the rows are counted as drops and
// discarded.
func (s *clickhouseSink) EnqueueEvents(ctx context.Context, rows []RouteEventRow) {
	if s == nil || len(rows) == 0 {
		return
	}
	cp := make([]RouteEventRow, len(rows))
	copy(cp, rows)
	if s.mode == queueModeBlock {
		select {
		case s.eventsCh <- cp:
			return
		default:
		}
		s.queueBlocks.Add(uint64(len(cp)))
		s.blocksSinceLog.Add(uint64(len(cp)))
		s.maybeLogBlocks()
		select {
		case s.eventsCh <- cp:
		case <-ctx.Done():
		case <-s.ctx.Done():
		}
		return
	}
	select {
	case s.eventsCh <- cp:
	default:
		s.queueDrops.Add(uint64(len(cp)))
		s.dropsSinceLog.Add(uint64(len(cp)))
		s.maybeLogDrops()
	}
}

func (s *clickhouseSink) EnqueuePeers(ctx context.Context, rows []PeerRow) {
	if s == nil || len(rows) == 0 {
		return
	}
	cp := make([]PeerRow, len(rows))
	copy(cp, rows)
	if s.mode == queueModeBlock {
		select {
		case s.peersCh <- cp:
			return
		default:
		}
		s.queueBlocks.Add(uint64(len(cp)))
		s.blocksSinceLog.Add(uint64(len(cp)))
		s.maybeLogBlocks()
		select {
		case s.peersCh <- cp:
		case <-ctx.Done():
		case <-s.ctx.Done():
		}
		return
	}
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
	s.log.Warn("bmpgrapes clickhouse queue full (drop mode)",
		"dropped_rows_last_second", dropped,
		"queue_drops_total", s.queueDrops.Load(),
		"events_written_total", s.eventsWritten.Load(),
		"peers_written_total", s.peersWritten.Load(),
	)
}

func (s *clickhouseSink) maybeLogBlocks() {
	if !s.blockLogMu.TryLock() {
		return
	}
	defer s.blockLogMu.Unlock()
	now := time.Now()
	if now.Sub(s.lastBlockLog) < 5*time.Second {
		return
	}
	s.lastBlockLog = now
	blocked := s.blocksSinceLog.Swap(0)
	if blocked == 0 {
		return
	}
	s.log.Warn("bmpgrapes clickhouse queue saturated (applying back-pressure)",
		"blocked_rows_last_window", blocked,
		"queue_blocks_total", s.queueBlocks.Load(),
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
		"queue_blocks", s.queueBlocks.Load(),
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
		"queue_blocks", s.queueBlocks.Load(),
		"queue_mode", s.mode.String(),
	)
}

func (s *clickhouseSink) HealthSnapshot() clickhouseHealthSnapshot {
	if s == nil {
		return clickhouseHealthSnapshot{}
	}
	eventsQueued := s.eventsQueued.Load()
	eventsWritten := s.eventsWritten.Load()
	peersQueued := s.peersQueued.Load()
	peersWritten := s.peersWritten.Load()
	eventsLag := uint64(0)
	if eventsQueued > eventsWritten {
		eventsLag = eventsQueued - eventsWritten
	}
	peersLag := uint64(0)
	if peersQueued > peersWritten {
		peersLag = peersQueued - peersWritten
	}
	return clickhouseHealthSnapshot{
		EventsQueued:  eventsQueued,
		EventsWritten: eventsWritten,
		PeersQueued:   peersQueued,
		PeersWritten:  peersWritten,
		InsertErrs:    s.insertErrs.Load(),
		QueueDrops:    s.queueDrops.Load(),
		QueueBlocks:   s.queueBlocks.Load(),
		EventsLagRows: eventsLag,
		PeersLagRows:  peersLag,
		EventsQueue:   len(s.eventsCh),
		PeersQueue:    len(s.peersCh),
	}
}
