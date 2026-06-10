package main

import (
	"testing"
	"time"
)

func aggKey(srcPort, dstPort uint16) FlowKey {
	k := FlowKey{SrcPort: srcPort, DstPort: dstPort, Proto: 6, IPVersion: 4}
	k.SrcAddr[0], k.SrcAddr[1], k.SrcAddr[2], k.SrcAddr[3] = 10, 0, 0, 1
	k.DstAddr[0], k.DstAddr[1], k.DstAddr[2], k.DstAddr[3] = 10, 0, 0, 2
	return k
}

func TestAggregatorMergesSlicesIntoOneFlow(t *testing.T) {
	a := newFlowAggregator(15*time.Second, 60*time.Second, 1000)
	k := aggKey(1111, 80)

	// Two drain slices of the same flow, 1s apart.
	a.Merge([]flowKV{{k: k, v: FlowValue{Packets: 3, Bytes: 300, FirstSeenNs: 1_000, LastSeenNs: 2_000}}})
	a.Merge([]flowKV{{k: k, v: FlowValue{Packets: 5, Bytes: 700, FirstSeenNs: 2_500, LastSeenNs: 3_000}}})

	if a.Len() != 1 {
		t.Fatalf("want 1 cached flow, got %d", a.Len())
	}
	got := a.m[k]
	if got.Packets != 8 || got.Bytes != 1000 {
		t.Fatalf("counters not summed: packets=%d bytes=%d", got.Packets, got.Bytes)
	}
	if got.FirstSeenNs != 1_000 {
		t.Fatalf("first_seen should be earliest: %d", got.FirstSeenNs)
	}
	if got.LastSeenNs != 3_000 {
		t.Fatalf("last_seen should be latest: %d", got.LastSeenNs)
	}
}

func TestAggregatorExportsOnIdleAndActiveTimeout(t *testing.T) {
	idle := 10 * time.Second
	active := 60 * time.Second
	a := newFlowAggregator(idle, active, 1000)

	idleFlow := aggKey(1, 80)
	activeFlow := aggKey(2, 80)
	freshFlow := aggKey(3, 80)

	now := uint64(100 * time.Second)
	// idleFlow: last seen 11s ago -> idle expired.
	a.Merge([]flowKV{{k: idleFlow, v: FlowValue{Packets: 1, Bytes: 1, FirstSeenNs: now - uint64(20*time.Second), LastSeenNs: now - uint64(11*time.Second)}}})
	// activeFlow: still active (last seen now) but alive 61s -> active expired.
	a.Merge([]flowKV{{k: activeFlow, v: FlowValue{Packets: 1, Bytes: 1, FirstSeenNs: now - uint64(61*time.Second), LastSeenNs: now}}})
	// freshFlow: alive 5s, last seen now -> keep.
	a.Merge([]flowKV{{k: freshFlow, v: FlowValue{Packets: 1, Bytes: 1, FirstSeenNs: now - uint64(5*time.Second), LastSeenNs: now}}})

	out := a.Collect(now)
	if len(out) != 2 {
		t.Fatalf("want 2 expired flows, got %d", len(out))
	}
	if a.Len() != 1 {
		t.Fatalf("freshFlow should remain cached, got %d entries", a.Len())
	}
	if _, ok := a.m[freshFlow]; !ok {
		t.Fatalf("freshFlow evicted unexpectedly")
	}
}

func TestAggregatorCapEvictsOldest(t *testing.T) {
	a := newFlowAggregator(1*time.Hour, 1*time.Hour, 2) // long timeouts so only cap triggers
	now := uint64(1_000 * time.Second)

	for i := 0; i < 5; i++ {
		k := aggKey(uint16(100+i), 80)
		// older index => smaller last_seen
		a.Merge([]flowKV{{k: k, v: FlowValue{Packets: 1, Bytes: 1, FirstSeenNs: now, LastSeenNs: now - uint64(i)*uint64(time.Second)}}})
	}

	out := a.Collect(now)
	if a.Len() != 2 {
		t.Fatalf("cache should be capped at 2, got %d", a.Len())
	}
	if len(out) != 3 {
		t.Fatalf("want 3 evicted, got %d", len(out))
	}
	if a.Metrics().ForcedEvicted != 3 {
		t.Fatalf("forced eviction metric wrong: %d", a.Metrics().ForcedEvicted)
	}
}

func TestAggregatorDrainAll(t *testing.T) {
	a := newFlowAggregator(1*time.Hour, 1*time.Hour, 1000)
	a.Merge([]flowKV{
		{k: aggKey(1, 80), v: FlowValue{Packets: 1, Bytes: 1}},
		{k: aggKey(2, 80), v: FlowValue{Packets: 1, Bytes: 1}},
	})
	out := a.DrainAll()
	if len(out) != 2 {
		t.Fatalf("want 2 drained, got %d", len(out))
	}
	if a.Len() != 0 {
		t.Fatalf("cache should be empty after DrainAll, got %d", a.Len())
	}
}
