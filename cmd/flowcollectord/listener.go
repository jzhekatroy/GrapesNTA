package main

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"xdpflowd/internal/flowingest"
)

type sflowListener struct {
	log        *slog.Logger
	addr       string
	sourceID   string
	readBuf    int
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
	return &sflowListener{
		log:        log,
		addr:       addr,
		sourceID:   sourceID,
		readBuf:    readBuf,
		batchSize:  batchSize,
		flushEvery: flushEvery,
		delivery:   delivery,
		classifier: classifier,
	}
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
	)

	buf := make([]byte, datagramBufSize)
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
	for {
		if ctx.Err() != nil {
			flush()
			return ctx.Err()
		}
		deadline := time.Now().Add(time.Second)
		if nextFlush.Before(deadline) {
			deadline = nextFlush
		}
		_ = pc.SetReadDeadline(deadline)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Now().After(nextFlush) || time.Now().Equal(nextFlush) {
					flush()
				}
				continue
			}
			if ctx.Err() != nil {
				flush()
				return ctx.Err()
			}
			l.log.Warn("sflow read", "err", err)
			continue
		}
		receivedAt := time.Now().UTC()
		seq := l.seq.Load()
		rows := parseSFlowV5(buf[:n], receivedAt, l.sourceID, l.classifier, &seq, &l.metrics)
		l.seq.Store(seq)
		if len(rows) > 0 {
			pending = append(pending, rows...)
			if len(pending) >= l.batchSize || time.Now().After(nextFlush) || time.Now().Equal(nextFlush) {
				flush()
			}
		}
	}
}

func (l *sflowListener) LogMetrics() {
	if l == nil {
		return
	}
	l.log.Info("sflow",
		"datagrams", l.metrics.datagrams,
		"flow_samples", l.metrics.flowSamples,
		"records_parsed", l.metrics.recordsParsed,
		"counter_skipped", l.metrics.counterSkipped,
		"parse_errors", l.metrics.parseErrors,
		"unknown_samples", l.metrics.unknownSamples,
	)
}
