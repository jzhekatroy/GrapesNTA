//go:build linux

package main

import (
	"testing"
	"time"
)

func TestAnswersDeduperSuppressesWithinTTL(t *testing.T) {
	d := newAnswersDeduper(60 * time.Second)
	base := time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)
	row := sampleResponseRow()
	row.Ts = base

	first := d.Filter([]DNSAnswerRow{dnsAnswersFromRow(row)[0]})
	if len(first) != 1 {
		t.Fatalf("first len=%d want 1", len(first))
	}
	second := d.Filter([]DNSAnswerRow{dnsAnswersFromRow(row)[0]})
	if len(second) != 0 {
		t.Fatalf("second len=%d want 0", len(second))
	}
	if got := d.Suppressed(); got != 1 {
		t.Fatalf("suppressed=%d want 1", got)
	}
}

func TestAnswersDeduperAllowsAfterTTL(t *testing.T) {
	d := newAnswersDeduper(30 * time.Second)
	row := sampleResponseRow()
	row.Ts = time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC)
	answer := dnsAnswersFromRow(row)[0]
	if len(d.Filter([]DNSAnswerRow{answer})) != 1 {
		t.Fatal("expected first emit")
	}

	answer.Ts = row.Ts.Add(31 * time.Second)
	if len(d.Filter([]DNSAnswerRow{answer})) != 1 {
		t.Fatal("expected re-emit after ttl")
	}
}
