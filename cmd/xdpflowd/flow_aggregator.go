package main

import (
	"sort"
	"time"
)

// flowAggregator is a userspace flow cache that sits between the frequent BPF
// map drain and the (expensive) export to ClickHouse / NetFlow.
//
// WHY: in batch full-drain mode the BPF map must be emptied every few seconds
// so it never overflows (no map_full loss). But emptying it does NOT mean a
// flow ended — a long-lived connection reappears in the next drain with fresh
// counters. If every drain slice is written straight to ClickHouse, one real
// flow becomes N rows (N = active_timeout / drain_interval), which is what
// overwhelmed the insert path and filled the spool/disk.
//
// The aggregator folds drain slices back into one entry per flow key, summing
// bytes/packets and keeping the earliest first_seen / latest last_seen. A flow
// is only emitted once it is idle (no slice for idle_timeout) or has lived
// longer than active_timeout. The result is ~1 row per real flow per active
// window — the row rate drops by the same N factor.
//
// Not safe for concurrent use: it is driven entirely from the single export
// goroutine (the main select loop), so it needs no locking.
type flowAggregator struct {
	idleNs     uint64
	activeNs   uint64
	maxEntries int

	m map[FlowKey]FlowValue

	// metrics (monotonic counters; read for the periodic stats line)
	mergedIn      uint64 // drain slices folded in
	exportedOut   uint64 // flows emitted on idle/active expiry
	forcedEvicted uint64 // flows force-emitted because the cap was hit
}

func newFlowAggregator(idle, active time.Duration, maxEntries int) *flowAggregator {
	if idle <= 0 {
		idle = 15 * time.Second
	}
	if active <= 0 {
		active = 60 * time.Second
	}
	if maxEntries < 1 {
		maxEntries = 2_000_000
	}
	return &flowAggregator{
		idleNs:     uint64(idle),
		activeNs:   uint64(active),
		maxEntries: maxEntries,
		m:          make(map[FlowKey]FlowValue, 4096),
	}
}

// Merge folds a freshly drained chunk into the cache. The chunk's backing
// buffers may be reused by the caller after this returns: FlowKey/FlowValue are
// plain value types, so the map stores copies.
func (a *flowAggregator) Merge(chunk []flowKV) {
	for i := range chunk {
		k := chunk[i].k
		if cur, ok := a.m[k]; ok {
			a.m[k] = mergeFlowValue(cur, chunk[i].v)
		} else {
			a.m[k] = chunk[i].v
		}
	}
	a.mergedIn += uint64(len(chunk))
}

// Collect removes and returns every flow that has crossed idle or active
// timeout, plus (if over the entry cap) the oldest flows needed to get back
// under the cap. The returned slice is ready to hand to the NetFlow/ClickHouse
// export paths exactly like a raw drain chunk.
func (a *flowAggregator) Collect(nowMonoNs uint64) []flowKV {
	var out []flowKV
	for k, v := range a.m {
		if a.expired(nowMonoNs, v) {
			out = append(out, flowKV{k: k, v: v})
			delete(a.m, k)
		}
	}
	a.exportedOut += uint64(len(out))

	if len(a.m) > a.maxEntries {
		out = a.evictOldest(out)
	}
	return out
}

// DrainAll removes and returns the entire cache (used on shutdown so nothing is
// left behind).
func (a *flowAggregator) DrainAll() []flowKV {
	if len(a.m) == 0 {
		return nil
	}
	out := make([]flowKV, 0, len(a.m))
	for k, v := range a.m {
		out = append(out, flowKV{k: k, v: v})
	}
	a.exportedOut += uint64(len(out))
	a.m = make(map[FlowKey]FlowValue, 4096)
	return out
}

func (a *flowAggregator) expired(nowMonoNs uint64, v FlowValue) bool {
	var idle, lifetime uint64
	if nowMonoNs > v.LastSeenNs {
		idle = nowMonoNs - v.LastSeenNs
	}
	if nowMonoNs > v.FirstSeenNs {
		lifetime = nowMonoNs - v.FirstSeenNs
	}
	return idle >= a.idleNs || lifetime >= a.activeNs
}

// evictOldest force-emits the oldest entries (by last_seen) until the cache is
// back under maxEntries. This bounds memory under pathological flow
// cardinality (e.g. a DDoS with millions of unique tuples). Sustained eviction
// is the signal to enable sampling upstream.
func (a *flowAggregator) evictOldest(out []flowKV) []flowKV {
	overflow := len(a.m) - a.maxEntries
	if overflow <= 0 {
		return out
	}
	type ks struct {
		k    FlowKey
		last uint64
	}
	all := make([]ks, 0, len(a.m))
	for k, v := range a.m {
		all = append(all, ks{k: k, last: v.LastSeenNs})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].last < all[j].last })
	for i := 0; i < overflow && i < len(all); i++ {
		k := all[i].k
		out = append(out, flowKV{k: k, v: a.m[k]})
		delete(a.m, k)
	}
	a.forcedEvicted += uint64(overflow)
	a.exportedOut += uint64(overflow)
	return out
}

// Len reports the current number of cached flows (memory footprint proxy).
func (a *flowAggregator) Len() int { return len(a.m) }

type aggMetrics struct {
	Entries       int
	MergedIn      uint64
	ExportedOut   uint64
	ForcedEvicted uint64
}

func (a *flowAggregator) Metrics() aggMetrics {
	return aggMetrics{
		Entries:       len(a.m),
		MergedIn:      a.mergedIn,
		ExportedOut:   a.exportedOut,
		ForcedEvicted: a.forcedEvicted,
	}
}

// mergeFlowValue folds slice b into accumulated a. Counters sum; first/last
// seen take the widest span; the metadata fields (only used by NetFlow, not
// written to flows_raw) take sensible min/max/OR so an aggregated flow still
// describes the whole connection.
func mergeFlowValue(a, b FlowValue) FlowValue {
	a.Packets += b.Packets
	a.Bytes += b.Bytes
	if b.FirstSeenNs < a.FirstSeenNs {
		a.FirstSeenNs = b.FirstSeenNs
	}
	if b.LastSeenNs > a.LastSeenNs {
		a.LastSeenNs = b.LastSeenNs
	}
	a.TCPSynCount += b.TCPSynCount
	a.TCPRstCount += b.TCPRstCount
	a.TCPFinCount += b.TCPFinCount
	a.TCPFlagsOR |= b.TCPFlagsOR
	a.IPFragCount += b.IPFragCount
	if b.TTLMin != 0 && (a.TTLMin == 0 || b.TTLMin < a.TTLMin) {
		a.TTLMin = b.TTLMin
	}
	if b.TTLMax > a.TTLMax {
		a.TTLMax = b.TTLMax
	}
	if b.PktLenMin != 0 && (a.PktLenMin == 0 || b.PktLenMin < a.PktLenMin) {
		a.PktLenMin = b.PktLenMin
	}
	if b.PktLenMax > a.PktLenMax {
		a.PktLenMax = b.PktLenMax
	}
	if b.IngressIf != 0 {
		a.IngressIf = b.IngressIf
	}
	if b.RxQueue != 0 {
		a.RxQueue = b.RxQueue
	}
	if b.Tos != 0 {
		a.Tos = b.Tos
	}
	return a
}
