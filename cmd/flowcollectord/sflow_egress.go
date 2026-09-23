package main

import (
	"sync"
	"time"
)

// A switch that samples a port in both directions reports a transiting packet
// twice: once on the ingress of the port it entered and once on the egress of
// the port it left. Both copies carry the same input and output ifIndex, so
// summing them doubles the traffic. An egress copy is redundant only when the
// packet's input port also samples ingress; otherwise it is the sole copy.
const sflowIngressPortTTL = 10 * time.Minute

type sflowPortKey struct {
	sampler [16]byte
	ifIndex uint32
}

type sflowIngressPorts struct {
	mu   sync.RWMutex
	seen map[sflowPortKey]time.Time
}

func newSFlowIngressPorts() *sflowIngressPorts {
	return &sflowIngressPorts{seen: make(map[sflowPortKey]time.Time)}
}

// mark records that ifIndex on sampler reports ingress samples. The write lock
// is taken at most once a minute per port.
func (p *sflowIngressPorts) mark(sampler [16]byte, ifIndex uint32, now time.Time) {
	if p == nil || ifIndex == 0 {
		return
	}
	key := sflowPortKey{sampler: sampler, ifIndex: ifIndex}
	p.mu.RLock()
	last, ok := p.seen[key]
	p.mu.RUnlock()
	if ok && now.Sub(last) < time.Minute {
		return
	}
	p.mu.Lock()
	p.seen[key] = now
	p.mu.Unlock()
}

func (p *sflowIngressPorts) samplesIngress(sampler [16]byte, ifIndex uint32, now time.Time) bool {
	if p == nil || ifIndex == 0 {
		return false
	}
	p.mu.RLock()
	last, ok := p.seen[sflowPortKey{sampler: sampler, ifIndex: ifIndex}]
	p.mu.RUnlock()
	return ok && now.Sub(last) < sflowIngressPortTTL
}

type sflowSampleSide uint8

const (
	sflowSideUnknown sflowSampleSide = iota
	sflowSideIngress
	sflowSideEgress
)

// sflowSampleSideOf compares the data source of a flow sample with the decoded
// input and output ifIndex. Only ifIndex data sources (type 0) are compared.
func sflowSampleSideOf(dsType, dsIndex, inIf, outIf uint32) sflowSampleSide {
	if dsType != 0 || dsIndex == 0 {
		return sflowSideUnknown
	}
	switch {
	case dsIndex == inIf:
		return sflowSideIngress
	case dsIndex == outIf:
		return sflowSideEgress
	default:
		return sflowSideUnknown
	}
}
