//go:build linux

package afxdp

import (
	"sync"

	"xdpflowd/internal/netv9"
)

// FlowAgg is a userspace flow table (replaces the eBPF map for afxdpflowd).
type FlowAgg struct {
	mu    sync.Mutex
	m     map[netv9.FlowKey]*netv9.FlowValue
	max   int
	ifIdx uint32
	rxQ   uint32
	stats *Stats
}

// NewFlowAgg max is the max concurrent flows; extra inserts bump map_full in stats.
func NewFlowAgg(max int, ifIdx uint32, rxQ uint32, stats *Stats) *FlowAgg {
	if max <= 0 {
		max = 1_000_000
	}
	return &FlowAgg{
		m:     make(map[netv9.FlowKey]*netv9.FlowValue),
		max:   max,
		ifIdx: ifIdx,
		rxQ:   rxQ,
		stats: stats,
	}
}

// OnFrame parses frame and updates the flow table.
func (a *FlowAgg) OnFrame(frame []byte) {
	if a.stats != nil {
		a.stats.packets.Add(1)
		a.stats.bytes.Add(uint64(len(frame)))
	}
	k, meta, ok, parseErr := ParseIPFrame(frame)
	if parseErr {
		if a.stats != nil {
			a.stats.parseErr.Add(1)
		}
		return
	}
	if !ok {
		if a.stats != nil {
			a.stats.nonIP.Add(1)
		}
		return
	}
	if a.stats != nil {
		if k.IPVersion == 4 {
			a.stats.ipv4.Add(1)
		} else {
			a.stats.ipv6.Add(1)
		}
	}
	a.merge(k, meta)
}

func (a *FlowAgg) merge(k netv9.FlowKey, meta PktMeta) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.m[k]
	if !ok {
		if len(a.m) >= a.max {
			if a.stats != nil {
				a.stats.mapFull.Add(1)
			}
			return
		}
		v = &netv9.FlowValue{
			Packets:     1,
			Bytes:       uint64(meta.PktLen),
			FirstSeenNs: meta.Now,
			LastSeenNs:  meta.Now,
			IngressIf:   a.ifIdx,
			RxQueue:     a.rxQ,
			TCPSynCount: meta.Acc.SynCnt,
			TCPRstCount: meta.Acc.RstCnt,
			TCPFinCount: meta.Acc.FinCnt,
			TCPFlagsOR:  meta.Acc.Flags,
			Tos:         meta.Tos,
			TTLMin:      meta.TTL,
			TTLMax:      meta.TTL,
			PktLenMin:   meta.WireLen,
			PktLenMax:   meta.WireLen,
			IPFragCount: uint32(meta.FragIncr),
		}
		a.m[k] = v
		return
	}
	v.Packets++
	v.Bytes += uint64(meta.PktLen)
	v.LastSeenNs = meta.Now
	v.TCPFlagsOR |= meta.Acc.Flags
	v.TCPSynCount += meta.Acc.SynCnt
	v.TCPRstCount += meta.Acc.RstCnt
	v.TCPFinCount += meta.Acc.FinCnt
	mergeTTL(v, meta.TTL)
	mergePktLen(v, meta.WireLen)
	if meta.FragIncr != 0 {
		v.IPFragCount++
	}
}

func mergeTTL(v *netv9.FlowValue, ttl uint8) {
	if ttl < v.TTLMin {
		v.TTLMin = ttl
	}
	if ttl > v.TTLMax {
		v.TTLMax = ttl
	}
}

func mergePktLen(v *netv9.FlowValue, plen uint16) {
	if plen < v.PktLenMin {
		v.PktLenMin = plen
	}
	if plen > v.PktLenMax {
		v.PktLenMax = plen
	}
}

// ScanAndExport exports flows that exceeded idle or active time (ns resolution).
func (a *FlowAgg) ScanAndExport(e *netv9.Exporter) int {
	now, err := netv9.MonoNow()
	if err != nil {
		return 0
	}
	idleNs := uint64(e.IdleTimeout)
	actNs := uint64(e.ActiveTimeout)
	var keys []netv9.FlowKey
	var vals []netv9.FlowValue
	a.mu.Lock()
	for k, v := range a.m {
		var idle, life uint64
		if now > v.LastSeenNs {
			idle = now - v.LastSeenNs
		}
		if now > v.FirstSeenNs {
			life = now - v.FirstSeenNs
		}
		if idle >= idleNs || life >= actNs {
			keys = append(keys, k)
			vals = append(vals, *v)
		}
	}
	for _, k := range keys {
		delete(a.m, k)
	}
	a.mu.Unlock()
	if len(keys) == 0 {
		return 0
	}
	e.ExportFlows(keys, vals)
	return len(keys)
}

// FlushAll exports every flow (shutdown).
func (a *FlowAgg) FlushAll(e *netv9.Exporter) int {
	var keys []netv9.FlowKey
	var vals []netv9.FlowValue
	a.mu.Lock()
	for k, v := range a.m {
		keys = append(keys, k)
		vals = append(vals, *v)
		delete(a.m, k)
	}
	a.mu.Unlock()
	if len(keys) == 0 {
		return 0
	}
	e.SendTemplate()
	e.ExportFlowsAfterTemplate(keys, vals)
	return len(keys)
}

// FlowsInMap returns the number of live flows (for logging).
func (a *FlowAgg) FlowsInMap() int {
	a.mu.Lock()
	n := len(a.m)
	a.mu.Unlock()
	return n
}
