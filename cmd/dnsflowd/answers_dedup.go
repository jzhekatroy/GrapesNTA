//go:build linux

package main

import (
	"sync"
	"sync/atomic"
	"time"
)

type answerDedupKey struct {
	clientIP   [16]byte
	answerIP   [16]byte
	queryName  string
	answerType string
}

type answersDeduper struct {
	ttl time.Duration
	mu  sync.Mutex
	// lastEmit is the timestamp of the last emitted row for this key.
	lastEmit map[answerDedupKey]time.Time

	suppressed atomic.Uint64
	emitted    atomic.Uint64
}

func newAnswersDeduper(ttl time.Duration) *answersDeduper {
	if ttl <= 0 {
		return nil
	}
	return &answersDeduper{
		ttl:      ttl,
		lastEmit: make(map[answerDedupKey]time.Time),
	}
}

func answerDedupKeyFromRow(r DNSAnswerRow) answerDedupKey {
	return answerDedupKey{
		clientIP:   r.ClientIP,
		answerIP:   r.AnswerIP,
		queryName:  r.QueryName,
		answerType: r.AnswerType,
	}
}

// Filter returns answer rows that should be enqueued. Repeats within ttl since the
// last emitted row for the same key are suppressed.
func (d *answersDeduper) Filter(rows []DNSAnswerRow) []DNSAnswerRow {
	if d == nil || len(rows) == 0 {
		return rows
	}
	out := make([]DNSAnswerRow, 0, len(rows))
	now := time.Now()
	cutoff := now.Add(-d.ttl)

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, r := range rows {
		key := answerDedupKeyFromRow(r)
		if last, ok := d.lastEmit[key]; ok && !last.Before(cutoff) {
			d.suppressed.Add(1)
			continue
		}
		d.lastEmit[key] = r.Ts
		out = append(out, r)
		d.emitted.Add(1)
	}

	if len(d.lastEmit) > 500000 {
		d.pruneLocked(cutoff)
	}
	return out
}

func (d *answersDeduper) pruneLocked(cutoff time.Time) {
	for k, ts := range d.lastEmit {
		if ts.Before(cutoff) {
			delete(d.lastEmit, k)
		}
	}
}

func (d *answersDeduper) Suppressed() uint64 {
	if d == nil {
		return 0
	}
	return d.suppressed.Load()
}

func (d *answersDeduper) Emitted() uint64 {
	if d == nil {
		return 0
	}
	return d.emitted.Load()
}
