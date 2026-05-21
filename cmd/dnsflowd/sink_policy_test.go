//go:build linux

package main

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

func TestEnqueueRowsShedsRawWhenAnswersLagHigh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := &dnsClickhouseSink{
		log:            slog.Default(),
		rawEnabled:     true,
		answersEnabled: true,
		rawCh:          make(chan []DNSRow, 8),
		answersCh:      make(chan []DNSAnswerRow, 8),
		ctx:            ctx,
		cancel:         cancel,
		rawShed: newRawShedController(slog.Default(), true, true, 10, 5, 10*time.Second),
	}
	s.rawShed.mu.Lock()
	s.rawShed.active = true
	s.rawShed.mu.Unlock()

	s.answersQueued.Store(100)
	s.answersWritten.Store(0)

	s.EnqueueRows([]DNSRow{sampleResponseRow()})

	if len(s.rawCh) != 0 {
		t.Fatalf("raw batches=%d want 0 when shed active", len(s.rawCh))
	}
	if got := s.rawShed.ShedTotal(); got != 1 {
		t.Fatalf("raw_shed_total=%d want 1", got)
	}
	select {
	case <-s.answersCh:
	default:
		t.Fatal("answers should still enqueue under raw shed")
	}
}
