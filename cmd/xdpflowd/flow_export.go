package main

import (
	"time"

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

// selectExpiredFlows walks the flows map and returns flows whose idle or active
// lifetime crosses thresholds (same rules as NetFlow exporter).
func selectExpiredFlows(objs *loader.Objects, idleTimeout, activeTimeout time.Duration, nowMonoNs uint64) []flowKV {
	var k FlowKey
	var v FlowValue
	iter := objs.Flows.Iterate()
	var out []flowKV

	for iter.Next(&k, &v) {
		var idle, lifetime uint64
		if nowMonoNs > v.LastSeenNs {
			idle = nowMonoNs - v.LastSeenNs
		}
		if nowMonoNs > v.FirstSeenNs {
			lifetime = nowMonoNs - v.FirstSeenNs
		}
		exportIt := idle >= uint64(idleTimeout) || lifetime >= uint64(activeTimeout)
		if !exportIt {
			continue
		}
		if k.IPVersion != 4 && k.IPVersion != 6 {
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
		if k.IPVersion != 4 && k.IPVersion != 6 {
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
