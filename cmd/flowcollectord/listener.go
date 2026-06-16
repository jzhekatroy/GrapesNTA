package main

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"xdpflowd/internal/flowingest"
)

type sflowListener struct {
	log        *slog.Logger
	addr       string
	sourceID   string
	readBuf    int
	workers    int
	queueSize  int
	batchSize  int
	flushEvery time.Duration
	delivery   *flowingest.Delivery
	classifier *flowingest.TrafficClassifier
	seq        atomic.Uint32
	metrics    sflowMetrics
}

func newSflowListener(
	log *slog.Logger,
	addr, sourceID string,
	readBuf int,
	workers int,
	queueSize int,
	batchSize int,
	flushEvery time.Duration,
	delivery *flowingest.Delivery,
	classifier *flowingest.TrafficClassifier,
) *sflowListener {
	if batchSize < 1 {
		batchSize = 1
	}
	if flushEvery <= 0 {
		flushEvery = time.Second
	}
	if workers < 1 {
		workers = 1
	}
	if queueSize < 1 {
		queueSize = 1
	}
	return &sflowListener{
		log:        log,
		addr:       addr,
		sourceID:   sourceID,
		readBuf:    readBuf,
		workers:    workers,
		queueSize:  queueSize,
		batchSize:  batchSize,
		flushEvery: flushEvery,
		delivery:   delivery,
		classifier: classifier,
	}
}

type sflowDatagram struct {
	b          []byte
	receivedAt time.Time
}

func (l *sflowListener) Run(ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp", l.addr)
	if err != nil {
		return err
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer pc.Close()
	if l.readBuf > 0 {
		if err := pc.SetReadBuffer(l.readBuf); err != nil {
			l.log.Warn("sflow set udp read buffer", "requested_bytes", l.readBuf, "err", err)
		}
	}
	datagramBufSize := l.readBuf
	if datagramBufSize < 65535 {
		datagramBufSize = 65535
	}
	l.log.Info("sflow listener started",
		"addr", l.addr,
		"source_id", l.sourceID,
		"udp_read_buffer_bytes", l.readBuf,
		"datagram_buffer_bytes", datagramBufSize,
		"udp_workers", l.workers,
		"udp_queue_size", l.queueSize,
	)

	datagrams := make(chan sflowDatagram, l.queueSize)
	var wg sync.WaitGroup
	for i := 0; i < l.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.runWorker(ctx, datagrams)
		}()
	}
	defer func() {
		close(datagrams)
		wg.Wait()
	}()

	buf := make([]byte, datagramBufSize)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := pc.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			l.log.Warn("sflow read", "err", err)
			continue
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])
		d := sflowDatagram{b: cp, receivedAt: time.Now().UTC()}
		select {
		case datagrams <- d:
		default:
			l.metrics.udpQueueDrops.Add(1)
		}
	}
}

func (l *sflowListener) runWorker(ctx context.Context, datagrams <-chan sflowDatagram) {
	pending := make([]flowingest.FlowRow, 0, l.batchSize)
	nextFlush := time.Now().Add(l.flushEvery)
	flush := func() {
		if len(pending) == 0 || l.delivery == nil {
			pending = pending[:0]
			nextFlush = time.Now().Add(l.flushEvery)
			return
		}
		l.delivery.EnqueueRows(pending)
		pending = make([]flowingest.FlowRow, 0, l.batchSize)
		nextFlush = time.Now().Add(l.flushEvery)
	}
	ticker := time.NewTicker(l.flushEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-ticker.C:
			if time.Now().After(nextFlush) || time.Now().Equal(nextFlush) {
				flush()
			}
		case d, ok := <-datagrams:
			if !ok {
				flush()
				return
			}
			rows := parseSFlowV5(d.b, d.receivedAt, l.sourceID, l.classifier, nil, &l.metrics)
			for i := range rows {
				rows[i].SequenceNum = l.seq.Add(1)
			}
			if len(rows) > 0 {
				pending = append(pending, rows...)
				if len(pending) >= l.batchSize || time.Now().After(nextFlush) || time.Now().Equal(nextFlush) {
					flush()
				}
			}
		}
	}
}

func (l *sflowListener) LogMetrics() {
	if l == nil {
		return
	}
	l.log.Info("sflow",
		"datagrams", l.metrics.datagrams.Load(),
		"flow_samples", l.metrics.flowSamples.Load(),
		"records_parsed", l.metrics.recordsParsed.Load(),
		"counter_skipped", l.metrics.counterSkipped.Load(),
		"parse_errors", l.metrics.parseErrors.Load(),
		"unknown_samples", l.metrics.unknownSamples.Load(),
		"udp_queue_drops", l.metrics.udpQueueDrops.Load(),
	)
}
