package main

import (
	"testing"
	"time"
)

// TestIsExpiredByTimers locks in the expiry predicate shared by the legacy
// snapshot path and the atomic LookupAndDelete drain path. Regression for the
// 2026-05-19 under-count: if the predicate ever silently changes shape, both
// paths drift and we lose flows.
func TestIsExpiredByTimers(t *testing.T) {
	const (
		idle   = 10 * time.Second
		active = 60 * time.Second
	)
	now := uint64(100 * time.Second)

	cases := []struct {
		name       string
		first, last uint64
		want       bool
	}{
		{
			name:  "fresh flow, well within both timers",
			first: uint64(95 * time.Second),
			last:  uint64(99 * time.Second),
			want:  false,
		},
		{
			name:  "idle exactly at threshold",
			first: uint64(95 * time.Second),
			last:  uint64(90 * time.Second),
			want:  true,
		},
		{
			name:  "idle just under threshold",
			first: uint64(95 * time.Second),
			last:  uint64(91 * time.Second),
			want:  false,
		},
		{
			name:  "active timeout reached even though flow is hot",
			first: uint64(40 * time.Second),
			last:  uint64(99 * time.Second),
			want:  true,
		},
		{
			name:  "active timeout exactly at boundary",
			first: uint64(40 * time.Second),
			last:  uint64(95 * time.Second),
			want:  true,
		},
		{
			name:  "lastSeen in the future (clock skew safety)",
			first: uint64(95 * time.Second),
			last:  uint64(150 * time.Second),
			want:  false,
		},
		{
			name:  "firstSeen in the future, flow still hot",
			first: uint64(150 * time.Second),
			last:  uint64(99 * time.Second),
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := FlowValue{FirstSeenNs: tc.first, LastSeenNs: tc.last}
			got := isExpiredByTimers(v, now, idle, active)
			if got != tc.want {
				t.Fatalf("isExpiredByTimers(first=%d, last=%d, now=%d, idle=%v, active=%v) = %v, want %v",
					tc.first, tc.last, now, idle, active, got, tc.want)
			}
		})
	}
}

// TestIsExportableKey guards that only IPv4/IPv6 keys leak into the export
// pipeline. Any other version is a logic bug (BPF should not emit them) and
// must be dropped before ClickHouse ever sees it.
func TestIsExportableKey(t *testing.T) {
	cases := []struct {
		v    uint8
		want bool
	}{
		{4, true},
		{6, true},
		{0, false},
		{1, false},
		{255, false},
	}
	for _, tc := range cases {
		k := FlowKey{IPVersion: tc.v}
		if got := isExportableKey(k); got != tc.want {
			t.Fatalf("isExportableKey(version=%d) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

// TestFlowDrainerNilSafe ensures a nil drainer doesn't panic and reports the
// legacy mode counters as zero. Used during tests / utility commands that
// don't build a drainer.
func TestFlowDrainerNilSafe(t *testing.T) {
	var d *FlowDrainer
	a, l := d.Counters()
	if a != 0 || l != 0 {
		t.Fatalf("nil drainer counters: got (%d,%d) want (0,0)", a, l)
	}
}

// TestFlowDrainerModeName covers the human-readable mode string used in
// journalctl. Locking it down so log parsing and dashboards stay stable.
func TestFlowDrainerModeName(t *testing.T) {
	cases := map[flowDrainerMode]string{
		flowDrainAtomic: "atomic",
		flowDrainLegacy: "legacy",
		flowDrainerMode(200): "unknown",
	}
	for in, want := range cases {
		if got := flowDrainerModeName(in); got != want {
			t.Fatalf("flowDrainerModeName(%d) = %q, want %q", in, got, want)
		}
	}
}
