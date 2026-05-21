//go:build linux

package main

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

func newTestSink(rawEnabled, answersEnabled bool, rawQueueSize, answersQueueSize int) *dnsClickhouseSink {
	ctx, cancel := context.WithCancel(context.Background())
	s := &dnsClickhouseSink{
		log:              slog.Default(),
		rawEnabled:       rawEnabled,
		answersEnabled:   answersEnabled,
		rawBatchSize:     500,
		answersBatchSize: 500,
		ctx:              ctx,
		cancel:           cancel,
	}
	if rawEnabled && rawQueueSize > 0 {
		s.rawCh = make(chan []DNSRow, rawQueueSize)
	}
	if answersEnabled && answersQueueSize > 0 {
		s.answersCh = make(chan []DNSAnswerRow, answersQueueSize)
	}
	return s
}

func sampleResponseRow() DNSRow {
	var a1, srv [16]byte
	copy(a1[:4], []byte{142, 250, 185, 174})
	copy(srv[:4], []byte{8, 8, 8, 8})
	return DNSRow{
		Ts:         time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC),
		ClientIP:   a1,
		ServerIP:   srv,
		IsResponse: 1,
		RCode:      0,
		QueryName:  "example.com",
		QType:      "A",
		AnswersA:   [][16]byte{a1},
		AnswersATTLs: []uint32{60},
		Transport:  "udp",
	}
}

func TestEnqueueRowsAnswersOnResponse(t *testing.T) {
	s := newTestSink(true, true, 8, 8)
	s.EnqueueRows([]DNSRow{sampleResponseRow()})

	select {
	case raw := <-s.rawCh:
		if len(raw) != 1 {
			t.Fatalf("raw batch len=%d want 1", len(raw))
		}
	default:
		t.Fatal("raw batch not enqueued")
	}
	select {
	case answers := <-s.answersCh:
		if len(answers) != 1 {
			t.Fatalf("answers len=%d want 1", len(answers))
		}
	default:
		t.Fatal("answers batch not enqueued")
	}
}

func TestEnqueueRowsSkipsQueryAndNXDOMAIN(t *testing.T) {
	s := newTestSink(true, true, 8, 8)
	s.EnqueueRows([]DNSRow{{IsResponse: 0, QueryName: "q.example.com"}})
	s.EnqueueRows([]DNSRow{{IsResponse: 1, RCode: 3, QueryName: "nx.example.com"}})

	if len(s.rawCh) != 2 {
		t.Fatalf("raw batches=%d want 2", len(s.rawCh))
	}
	if len(s.answersCh) != 0 {
		t.Fatalf("answers batches=%d want 0", len(s.answersCh))
	}
}

func TestEnqueueRowsRawDisabledAnswersStillEnqueue(t *testing.T) {
	s := newTestSink(false, true, 0, 8)
	s.EnqueueRows([]DNSRow{sampleResponseRow()})

	if s.rawCh != nil {
		t.Fatal("raw channel should be nil when raw disabled")
	}
	select {
	case answers := <-s.answersCh:
		if len(answers) != 1 {
			t.Fatalf("answers len=%d want 1", len(answers))
		}
	default:
		t.Fatal("answers not enqueued with raw disabled")
	}
}

func TestEnqueueRowsAnswersQueueDropsIndependent(t *testing.T) {
	s := newTestSink(true, true, 64, 1)
	row := sampleResponseRow()
	answers := dnsAnswersFromRow(row)

	s.enqueueAnswers(answers)
	s.enqueueAnswers(answers)

	if got := s.AnswersQueueDrops(); got != uint64(len(answers)) {
		t.Fatalf("answers_queue_drops=%d want %d", got, len(answers))
	}
	if got := s.RawQueueDrops(); got != 0 {
		t.Fatalf("raw_queue_drops=%d want 0", got)
	}
}

func TestEnqueueRowsRawQueueDropsIndependent(t *testing.T) {
	s := newTestSink(true, true, 1, 64)
	rows := []DNSRow{sampleResponseRow(), sampleResponseRow()}

	s.enqueueRaw(rows[:1])
	s.enqueueRaw(rows)

	if got := s.RawQueueDrops(); got != 2 {
		t.Fatalf("raw_queue_drops=%d want 2", got)
	}
	if got := s.AnswersQueueDrops(); got != 0 {
		t.Fatalf("answers_queue_drops=%d want 0", got)
	}
}
