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
	delivery   *flowingest.Delivery
	classifier *flowingest.TrafficClassifier
	seq        atomic.Uint32
	metrics    sflowMetrics
}

func newSflowListener(
	log *slog.Logger,
	addr, sourceID string,
	readBuf int,
	delivery *flowingest.Delivery,
	classifier *flowingest.TrafficClassifier,
) *sflowListener {
	return &sflowListener{
		log:        log,
		addr:       addr,
		sourceID:   sourceID,
		readBuf:    readBuf,
		delivery:   delivery,
		classifier: classifier,
	}
}

func (l *sflowListener) Run(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", l.addr)
	if err != nil {
		return err
	}
	defer pc.Close()
	l.log.Info("sflow listener started", "addr", l.addr, "source_id", l.sourceID)

	buf := make([]byte, l.readBuf)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := pc.ReadFrom(buf)
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
		receivedAt := time.Now().UTC()
		seq := l.seq.Load()
		rows := parseSFlowV5(buf[:n], receivedAt, l.sourceID, l.classifier, &seq, &l.metrics)
		l.seq.Store(seq)
		if len(rows) > 0 && l.delivery != nil {
			l.delivery.EnqueueRows(rows)
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
