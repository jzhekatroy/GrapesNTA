package main

import (
	"errors"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"
	"xdpflowd/internal/loader"
)

// flowKV is one accounted flow pulled from the BPF hash map for export.
type flowKV struct {
	k FlowKey
	v FlowValue
}

// ExportClock converts CLOCK_BOOTTIME-ish bpf timestamps (/proc/uptime) to wall time.
type ExportClock struct {
	ExporterStart time.Time
	BpfStartNs    uint64
}

func (c ExportClock) monoNsToWall(ns uint64) time.Time {
	if ns <= c.BpfStartNs {
		return c.ExporterStart
	}
	return c.ExporterStart.Add(time.Duration(ns - c.BpfStartNs))
}

// isExpiredByTimers returns true when the flow has crossed either idle or
// active timeout — pulled into a separate helper so the same predicate is
// covered by unit tests and shared between the atomic drain path and the
// legacy snapshot path.
func isExpiredByTimers(v FlowValue, nowMonoNs uint64, idleTimeout, activeTimeout time.Duration) bool {
	var idle, lifetime uint64
	if nowMonoNs > v.LastSeenNs {
		idle = nowMonoNs - v.LastSeenNs
	}
	if nowMonoNs > v.FirstSeenNs {
		lifetime = nowMonoNs - v.FirstSeenNs
	}
	return idle >= uint64(idleTimeout) || lifetime >= uint64(activeTimeout)
}

// isExportableKey filters flow keys that are not part of the IPv4/IPv6 flow
// space (must mirror the BPF program — anything else is a logic bug we drop
// to keep `flows_raw` clean).
func isExportableKey(k FlowKey) bool {
	return k.IPVersion == 4 || k.IPVersion == 6
}

// selectExpiredFlows walks the flows map and returns flows whose idle or active
// lifetime crosses thresholds (legacy path: snapshot only, no delete).
//
// IMPORTANT: this path is racy by design — between the snapshot here and the
// matching deleteFlowKeys call below, the BPF program on other CPUs may keep
// incrementing v.Packets/v.Bytes, and those increments are then discarded by
// the delete. Prefer drainExpiredFlows on kernels that support
// BPF_MAP_LOOKUP_AND_DELETE_ELEM for HASH maps (>= 5.14).
func selectExpiredFlows(objs *loader.Objects, idleTimeout, activeTimeout time.Duration, nowMonoNs uint64) []flowKV {
	var k FlowKey
	var v FlowValue
	iter := objs.Flows.Iterate()
	var out []flowKV

	for iter.Next(&k, &v) {
		if !isExpiredByTimers(v, nowMonoNs, idleTimeout, activeTimeout) {
			continue
		}
		if !isExportableKey(k) {
			continue
		}
		out = append(out, flowKV{k: k, v: v})
	}
	_ = iter.Err()
	return out
}

func selectAllFlows(objs *loader.Objects) []flowKV {
	var k FlowKey
	var v FlowValue
	iter := objs.Flows.Iterate()
	var out []flowKV
	for iter.Next(&k, &v) {
		if !isExportableKey(k) {
			continue
		}
		out = append(out, flowKV{k: k, v: v})
	}
	_ = iter.Err()
	return out
}

func deleteFlowKeys(objs *loader.Objects, flows []flowKV) int {
	n := 0
	for i := range flows {
		if err := objs.Flows.Delete(&flows[i].k); err == nil {
			n++
		}
	}
	return n
}

// drainExpiredFlows performs an atomic LookupAndDelete for every flow that has
// hit idle/active timeouts. The value returned is the BPF counters at the
// instant of the kernel-side delete, so packets accounted by XDP between the
// iteration step and the delete are NOT lost (this is the key correctness
// improvement vs. selectExpiredFlows + deleteFlowKeys).
//
// Caller must have verified support via probeAtomicFlowDrainSupport. On older
// kernels this function will return an empty slice with the first key's error
// stashed in the returned non-nil sentinel — callers should fall back to the
// legacy path.
func drainExpiredFlows(objs *loader.Objects, idleTimeout, activeTimeout time.Duration, nowMonoNs uint64) ([]flowKV, error) {
	// Phase 1: iterate to collect candidate keys. We do NOT take the value's
	// counters from the iterator — only the key — because the iterator
	// snapshot is racy. The final value comes from LookupAndDelete in phase 2.
	var k FlowKey
	var v FlowValue
	iter := objs.Flows.Iterate()
	var keys []FlowKey
	for iter.Next(&k, &v) {
		if !isExpiredByTimers(v, nowMonoNs, idleTimeout, activeTimeout) {
			continue
		}
		if !isExportableKey(k) {
			continue
		}
		keys = append(keys, k)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	// Phase 2: atomic per-key LookupAndDelete. Captures all counters the BPF
	// program may have added between the iterator visit and this call.
	out := make([]flowKV, 0, len(keys))
	for i := range keys {
		var fresh FlowValue
		if err := objs.Flows.LookupAndDelete(&keys[i], &fresh); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				// Another path (final flush race, restart cleanup) already
				// removed it — fine, just skip.
				continue
			}
			// LookupAndDelete became unsupported mid-run? Signal caller so
			// they can drop back to legacy mode for the rest of the lifetime.
			return out, err
		}
		out = append(out, flowKV{k: keys[i], v: fresh})
	}
	return out, nil
}

// flowBatchChunk is how many flows we pull per BPF_MAP_LOOKUP_AND_DELETE_BATCH
// syscall. Larger = fewer syscalls per drain; must be >= the map's bucket size
// or the kernel returns ENOSPC ("batch size too small"). 4096 is comfortably
// above any realistic bucket and keeps the per-call buffers small (~1 MB).
const flowBatchChunk = 4096

// flowStreamChunk bounds userspace memory for timer/atomic drain paths. The old
// implementation first collected every expired key and every exported flow into
// one large slice; on high-cardinality mirrors that transient heap reached tens
// of GB. Streaming keeps the timer semantics (idle/active expiry) while handing
// bounded chunks to the export sinks.
const flowStreamChunk = 16384

// streamBatchDrainAllFlows atomically pulls AND deletes every flow in the map
// using BPF_MAP_LOOKUP_AND_DELETE_BATCH. On a multi-million-entry map this
// replaces the O(N) per-key Iterate()+LookupAndDelete (tens of millions of
// syscalls per scan, which cannot complete inside a 1 s tick) with
// ~N/flowBatchChunk batch syscalls — fast enough to drain the whole table every
// few seconds so it never overflows. Counters are captured at the kernel-side
// delete, so it is as correct under load as the per-key atomic path.
//
// IMPORTANT: this function streams chunks to the caller. Do not accumulate the
// whole map into one []flowKV: at 5-12M flows that transient Go heap can push
// the collector into swap. The callback must consume/copy the chunk before
// returning because the backing batch buffers are reused on the next iteration.
//
// Semantics note: this drains EVERYTHING, so the export interval that calls it
// becomes the effective active timeout (there is no idle/active distinction).
// That is the intended trade-off for high-throughput collection.
func streamBatchDrainAllFlows(objs *loader.Objects, onChunk func([]flowKV) error) (int, error) {
	var cursor ebpf.MapBatchCursor
	keys := make([]FlowKey, flowBatchChunk)
	vals := make([]FlowValue, flowBatchChunk)
	total := 0
	for {
		n, err := objs.Flows.BatchLookupAndDelete(&cursor, keys, vals, nil)
		chunk := make([]flowKV, 0, n)
		for i := 0; i < n; i++ {
			if !isExportableKey(keys[i]) {
				continue
			}
			chunk = append(chunk, flowKV{k: keys[i], v: vals[i]})
		}
		if len(chunk) > 0 {
			if cbErr := onChunk(chunk); cbErr != nil {
				return total, cbErr
			}
			total += len(chunk)
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			// Reached the end of the map — all remaining results returned.
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// probeBatchDrainSupport returns true when BPF_MAP_LOOKUP_AND_DELETE_BATCH works
// (kernel >= 5.6 for hash maps). Probed on a throw-away map so the production
// flows map is never touched.
func probeBatchDrainSupport(log *slog.Logger) bool {
	spec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 16,
	}
	tmp, err := ebpf.NewMap(spec)
	if err != nil {
		if log != nil {
			log.Warn("batch drain probe: cannot create temporary HASH map; assuming unsupported", "err", err)
		}
		return false
	}
	defer tmp.Close()
	var k, v uint32 = 1, 1
	_ = tmp.Put(&k, &v)
	var cursor ebpf.MapBatchCursor
	keys := make([]uint32, 4)
	vals := make([]uint32, 4)
	_, err = tmp.BatchLookupAndDelete(&cursor, keys, vals, nil)
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return true
	}
	if log != nil {
		log.Warn("BPF_MAP_LOOKUP_AND_DELETE_BATCH not supported on this kernel; batch drain mode unavailable", "err", err)
	}
	return false
}

// drainAllFlows is the final-flush variant of drainExpiredFlows: it pulls
// every flow currently in the BPF map atomically. Used at shutdown so we
// don't lose trailing counters that no longer satisfy idle/active thresholds.
func drainAllFlows(objs *loader.Objects) ([]flowKV, error) {
	var k FlowKey
	var v FlowValue
	iter := objs.Flows.Iterate()
	var keys []FlowKey
	for iter.Next(&k, &v) {
		if !isExportableKey(k) {
			continue
		}
		keys = append(keys, k)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	out := make([]flowKV, 0, len(keys))
	for i := range keys {
		var fresh FlowValue
		if err := objs.Flows.LookupAndDelete(&keys[i], &fresh); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return out, err
		}
		out = append(out, flowKV{k: keys[i], v: fresh})
	}
	return out, nil
}

func streamExpiredFlowsAtomic(objs *loader.Objects, idleTimeout, activeTimeout time.Duration, nowMonoNs uint64, onChunk func([]flowKV) error) (int, error) {
	var cursor ebpf.MapBatchCursor
	keys := make([]FlowKey, flowStreamChunk)
	vals := make([]FlowValue, flowStreamChunk)
	total := 0

	for {
		n, err := objs.Flows.BatchLookup(&cursor, keys, vals, nil)
		out := make([]flowKV, 0, n)
		for i := 0; i < n; i++ {
			if !isExpiredByTimers(vals[i], nowMonoNs, idleTimeout, activeTimeout) {
				continue
			}
			if !isExportableKey(keys[i]) {
				continue
			}
			var fresh FlowValue
			if err := objs.Flows.LookupAndDelete(&keys[i], &fresh); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					continue
				}
				return total, err
			}
			out = append(out, flowKV{k: keys[i], v: fresh})
		}
		if len(out) > 0 {
			if err := onChunk(out); err != nil {
				return total, err
			}
			total += len(out)
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func streamExpiredFlowsLegacy(objs *loader.Objects, idleTimeout, activeTimeout time.Duration, nowMonoNs uint64, onChunk func([]flowKV) error) (exported, deleted int, err error) {
	var cursor ebpf.MapBatchCursor
	keys := make([]FlowKey, flowStreamChunk)
	vals := make([]FlowValue, flowStreamChunk)

	for {
		n, batchErr := objs.Flows.BatchLookup(&cursor, keys, vals, nil)
		chunk := make([]flowKV, 0, n)
		for i := 0; i < n; i++ {
			if !isExpiredByTimers(vals[i], nowMonoNs, idleTimeout, activeTimeout) {
				continue
			}
			if !isExportableKey(keys[i]) {
				continue
			}
			chunk = append(chunk, flowKV{k: keys[i], v: vals[i]})
		}
		if len(chunk) > 0 {
			if err := onChunk(chunk); err != nil {
				return exported, deleted, err
			}
			exported += len(chunk)
			deleted += deleteFlowKeys(objs, chunk)
		}
		if errors.Is(batchErr, ebpf.ErrKeyNotExist) {
			return exported, deleted, nil
		}
		if batchErr != nil {
			return exported, deleted, batchErr
		}
	}
}

func streamAllFlowsAtomic(objs *loader.Objects, onChunk func([]flowKV) error) (int, error) {
	var cursor ebpf.MapBatchCursor
	keys := make([]FlowKey, flowStreamChunk)
	vals := make([]FlowValue, flowStreamChunk)
	total := 0

	for {
		n, err := objs.Flows.BatchLookup(&cursor, keys, vals, nil)
		out := make([]flowKV, 0, n)
		for i := 0; i < n; i++ {
			if !isExportableKey(keys[i]) {
				continue
			}
			var fresh FlowValue
			if err := objs.Flows.LookupAndDelete(&keys[i], &fresh); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					continue
				}
				return total, err
			}
			out = append(out, flowKV{k: keys[i], v: fresh})
		}
		if len(out) > 0 {
			if err := onChunk(out); err != nil {
				return total, err
			}
			total += len(out)
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func streamAllFlowsLegacy(objs *loader.Objects, onChunk func([]flowKV) error) (exported, deleted int, err error) {
	var cursor ebpf.MapBatchCursor
	keys := make([]FlowKey, flowStreamChunk)
	vals := make([]FlowValue, flowStreamChunk)

	for {
		n, batchErr := objs.Flows.BatchLookup(&cursor, keys, vals, nil)
		chunk := make([]flowKV, 0, n)
		for i := 0; i < n; i++ {
			if !isExportableKey(keys[i]) {
				continue
			}
			chunk = append(chunk, flowKV{k: keys[i], v: vals[i]})
		}
		if len(chunk) > 0 {
			if err := onChunk(chunk); err != nil {
				return exported, deleted, err
			}
			exported += len(chunk)
			deleted += deleteFlowKeys(objs, chunk)
		}
		if errors.Is(batchErr, ebpf.ErrKeyNotExist) {
			return exported, deleted, nil
		}
		if batchErr != nil {
			return exported, deleted, batchErr
		}
	}
}

// probeAtomicFlowDrainSupport returns true when BPF_MAP_LOOKUP_AND_DELETE_ELEM
// works on a BPF_MAP_TYPE_HASH map (kernel >= 5.14). We probe on a temporary
// throw-away map so the production flows map is never touched.
//
// On false the caller must use the legacy snapshot+delete path (some packets
// will be under-counted under load — accepted on old kernels).
func probeAtomicFlowDrainSupport(log *slog.Logger) bool {
	spec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	tmp, err := ebpf.NewMap(spec)
	if err != nil {
		if log != nil {
			log.Warn("atomic flow drain probe: cannot create temporary HASH map; assuming unsupported", "err", err)
		}
		return false
	}
	defer tmp.Close()
	var k, v uint32
	err = tmp.LookupAndDelete(&k, &v)
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return true
	}
	if log != nil {
		log.Warn("BPF_MAP_LOOKUP_AND_DELETE_ELEM not supported on this kernel; falling back to snapshot+delete (may under-count under load)", "err", err)
	}
	return false
}

// flowDrainerMode selects between the atomic lookup-and-delete export path
// (correct under load) and the legacy snapshot+delete path (kept for kernels
// < 5.14). The chosen mode is captured once at startup; if the atomic path
// later returns an unexpected ENOTSUPP, the drainer auto-degrades to legacy
// for the remainder of the process lifetime and logs the transition.
type flowDrainerMode uint8

const (
	flowDrainAtomic flowDrainerMode = iota
	flowDrainLegacy
)

// FlowDrainer is the single entry point for "give me the flows that should
// leave the BPF map right now". It encapsulates kernel support detection and
// fallback so callers (ClickHouse direct path, NetFlow exporter) share one
// behaviour and one log surface.
type FlowDrainer struct {
	log              *slog.Logger
	mode             flowDrainerMode
	batchMode        bool   // operator requested batch full-drain (-drain-mode=batch)
	batchSupported   bool   // kernel supports BPF_MAP_LOOKUP_AND_DELETE_BATCH
	atomicCount      uint64 // bumped per call that used LookupAndDelete
	legacyCount      uint64 // bumped per call that fell back to Iterate+Delete
	batchCount       uint64 // bumped per call that used the batch full-drain
	demotedAtRuntime bool   // set when atomic was probed-supported but errored later

	// exclude drops operator-excluded flows from every chunk handed to the
	// export sinks. It runs here, and not in the sinks, because the drainer is
	// the one place both the NetFlow v9 encoder and the ClickHouse path go
	// through — one hook keeps the two exports byte-for-byte consistent.
	exclude func([]flowKV) []flowKV
}

// SetExclusionFilter installs the flow exclusion hook. Filtering happens after
// the BPF entries have been drained, so excluded flows still leave the map and
// cannot accumulate there.
func (d *FlowDrainer) SetExclusionFilter(fn func([]flowKV) []flowKV) {
	if d == nil {
		return
	}
	d.exclude = fn
}

// filtered wraps a chunk consumer so it only sees kept flows. The chunk the
// underlying drain helper holds is left intact: the legacy paths reuse it to
// issue the follow-up deletes.
func (d *FlowDrainer) filtered(onChunk func([]flowKV) error) func([]flowKV) error {
	if d == nil || d.exclude == nil || onChunk == nil {
		return onChunk
	}
	return func(chunk []flowKV) error {
		kept := d.exclude(chunk)
		if len(kept) == 0 {
			return nil
		}
		return onChunk(kept)
	}
}

// NewFlowDrainer picks the per-key drain mode (atomic vs legacy) and, when
// batchFull is requested and the kernel supports batch ops, enables the fast
// whole-map batch drain used by the high-throughput export path.
func NewFlowDrainer(log *slog.Logger, batchFull bool) *FlowDrainer {
	d := &FlowDrainer{log: log}
	if probeAtomicFlowDrainSupport(log) {
		d.mode = flowDrainAtomic
		if log != nil {
			log.Info("flow drainer: using atomic LookupAndDelete (kernel supports BPF_MAP_LOOKUP_AND_DELETE_ELEM)")
		}
	} else {
		d.mode = flowDrainLegacy
	}
	if batchFull {
		if probeBatchDrainSupport(log) {
			d.batchMode = true
			d.batchSupported = true
			if log != nil {
				log.Info("flow drainer: batch full-drain enabled (BPF_MAP_LOOKUP_AND_DELETE_BATCH); export interval is the effective active timeout")
			}
		} else if log != nil {
			log.Warn("flow drainer: batch full-drain requested but unsupported on this kernel; falling back to timer drain")
		}
	}
	return d
}

// BatchEnabled reports whether the fast whole-map batch drain is active.
func (d *FlowDrainer) BatchEnabled() bool {
	return d != nil && d.batchMode && d.batchSupported
}

// StreamFullBatchDrain pulls and deletes the entire flow map with batch ops,
// invoking onChunk for each small chunk. Entries are already removed from the
// map (no follow-up delete). This is the production batch path: it keeps memory
// bounded by flowBatchChunk instead of by the whole map cardinality.
func (d *FlowDrainer) StreamFullBatchDrain(objs *loader.Objects, onChunk func([]flowKV) error) (int, error) {
	n, err := streamBatchDrainAllFlows(objs, d.filtered(onChunk))
	if d != nil {
		d.batchCount++
	}
	return n, err
}

// Mode reports the active drainer mode (mostly for tests / log lines).
func (d *FlowDrainer) Mode() flowDrainerMode { return d.mode }

// flowDrainerModeName turns the internal mode constant into a stable string for
// logs and tests.
func flowDrainerModeName(m flowDrainerMode) string {
	switch m {
	case flowDrainAtomic:
		return "atomic"
	case flowDrainLegacy:
		return "legacy"
	default:
		return "unknown"
	}
}

// Counters returns (atomicCalls, legacyCalls) — useful for periodic stats.
func (d *FlowDrainer) Counters() (uint64, uint64) {
	if d == nil {
		return 0, 0
	}
	return d.atomicCount, d.legacyCount
}

// BatchCalls returns how many whole-map batch drains have run.
func (d *FlowDrainer) BatchCalls() uint64 {
	if d == nil {
		return 0
	}
	return d.batchCount
}

func (d *FlowDrainer) demoteToLegacy(err error) {
	if d.mode == flowDrainLegacy {
		return
	}
	d.mode = flowDrainLegacy
	d.demotedAtRuntime = true
	if d.log != nil {
		d.log.Warn("flow drainer: atomic path failed at runtime; degrading to legacy snapshot+delete", "err", err)
	}
}

// Expired returns flows that crossed idle/active timeouts. On the atomic path
// the returned values are post-LookupAndDelete (BPF counters at the instant of
// the kernel-side delete). The caller MUST NOT call deleteFlowKeys on the
// atomic-path result; the entries are already gone.
//
// On the legacy path the caller MUST follow up with deleteFlowKeys to actually
// remove the flows from the map (the snapshot leaves them in place). This
// matches the original two-step contract.
func (d *FlowDrainer) Expired(objs *loader.Objects, idleTimeout, activeTimeout time.Duration, nowMonoNs uint64) ([]flowKV, bool) {
	if d == nil || d.mode == flowDrainLegacy {
		if d != nil {
			d.legacyCount++
		}
		return selectExpiredFlows(objs, idleTimeout, activeTimeout, nowMonoNs), false
	}
	out, err := drainExpiredFlows(objs, idleTimeout, activeTimeout, nowMonoNs)
	if err != nil {
		d.demoteToLegacy(err)
		// Don't double-delete the few already removed by drainExpiredFlows;
		// fall through and let the snapshot path handle the next round.
		d.legacyCount++
		return selectExpiredFlows(objs, idleTimeout, activeTimeout, nowMonoNs), false
	}
	d.atomicCount++
	return out, true
}

// StreamExpired is the memory-bounded variant of Expired. It preserves the
// timer/atomic semantics (only idle/active-expired flows leave the map) but
// exports bounded chunks instead of building one large []flowKV.
func (d *FlowDrainer) StreamExpired(objs *loader.Objects, idleTimeout, activeTimeout time.Duration, nowMonoNs uint64, onChunk func([]flowKV) error) (exported, deleted int, atomicDrained bool, err error) {
	onChunk = d.filtered(onChunk)
	if onChunk == nil {
		onChunk = func([]flowKV) error { return nil }
	}
	if d == nil || d.mode == flowDrainLegacy {
		if d != nil {
			d.legacyCount++
		}
		exported, deleted, err = streamExpiredFlowsLegacy(objs, idleTimeout, activeTimeout, nowMonoNs, onChunk)
		return exported, deleted, false, err
	}
	n, err := streamExpiredFlowsAtomic(objs, idleTimeout, activeTimeout, nowMonoNs, onChunk)
	if err != nil {
		d.demoteToLegacy(err)
		return n, n, true, err
	}
	d.atomicCount++
	return n, n, true, nil
}

// All is the final-flush variant: pulls every IPv4/IPv6 flow currently in the
// map. Same contract as Expired regarding atomic vs legacy delete.
func (d *FlowDrainer) All(objs *loader.Objects) ([]flowKV, bool) {
	if d == nil || d.mode == flowDrainLegacy {
		if d != nil {
			d.legacyCount++
		}
		return selectAllFlows(objs), false
	}
	out, err := drainAllFlows(objs)
	if err != nil {
		d.demoteToLegacy(err)
		d.legacyCount++
		return selectAllFlows(objs), false
	}
	d.atomicCount++
	return out, true
}

// StreamAll is the memory-bounded final-flush variant. It is intended for
// shutdown and should not be used as the steady-state export mode.
func (d *FlowDrainer) StreamAll(objs *loader.Objects, onChunk func([]flowKV) error) (exported, deleted int, atomicDrained bool, err error) {
	onChunk = d.filtered(onChunk)
	if onChunk == nil {
		onChunk = func([]flowKV) error { return nil }
	}
	if d == nil || d.mode == flowDrainLegacy {
		if d != nil {
			d.legacyCount++
		}
		exported, deleted, err = streamAllFlowsLegacy(objs, onChunk)
		return exported, deleted, false, err
	}
	n, err := streamAllFlowsAtomic(objs, onChunk)
	if err != nil {
		d.demoteToLegacy(err)
		return n, n, true, err
	}
	d.atomicCount++
	return n, n, true, nil
}
