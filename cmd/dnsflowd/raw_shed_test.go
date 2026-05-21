//go:build linux

package main

import (
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestRawShedActivatesAndRecovers(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	c := newRawShedController(log, true, true, 100, 50, 100*time.Millisecond)

	c.Update(150, 10)
	if !c.ShedActive() {
		t.Fatal("expected shed active")
	}
	if c.ShouldEnqueueRaw() {
		t.Fatal("raw enqueue should be blocked while shedding")
	}

	c.Update(40, 0)
	if c.ShedActive() {
		t.Fatal("expected shed still active before cooldown")
	}

	time.Sleep(150 * time.Millisecond)
	c.Update(40, 0)
	if c.ShedActive() {
		t.Fatal("expected shed recovered after cooldown")
	}
	if !c.ShouldEnqueueRaw() {
		t.Fatal("raw enqueue should resume after recovery")
	}
}

func TestRawShedDisabledAlwaysEnqueues(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	c := newRawShedController(log, false, true, 100, 50, time.Second)
	c.Update(1_000_000, 999)
	if !c.ShouldEnqueueRaw() {
		t.Fatal("auto shed disabled should not block raw")
	}
}
