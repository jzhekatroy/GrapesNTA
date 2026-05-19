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
	atomicCount      uint64 // bumped per call that used LookupAndDelete
	legacyCount      uint64 // bumped per call that fell back to Iterate+Delete
	demotedAtRuntime bool   // set when atomic was probed-supported but errored later
}

func NewFlowDrainer(log *slog.Logger) *FlowDrainer {
	d := &FlowDrainer{log: log}
	if probeAtomicFlowDrainSupport(log) {
		d.mode = flowDrainAtomic
		if log != nil {
			log.Info("flow drainer: using atomic LookupAndDelete (kernel supports BPF_MAP_LOOKUP_AND_DELETE_ELEM)")
		}
	} else {
		d.mode = flowDrainLegacy
	}
	return d
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
