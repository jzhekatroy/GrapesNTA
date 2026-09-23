package main

import (
	"encoding/binary"
	"testing"
	"time"
)

// Offsets of the first flow sample inside a test datagram with an IPv4 agent:
// 28 bytes of datagram header plus 8 bytes of sample type and length.
const testFirstSampleOff = 36

func expandedSample(t *testing.T, inIf, outIf, dsIndex uint32) []byte {
	t.Helper()
	dgram := buildTestExpandedSFlowDatagramWithIfaces(t, buildTestIPv4UDPDatagram(), 8192, 0, inIf, 0, outIf)
	binary.BigEndian.PutUint32(dgram[testFirstSampleOff+4:testFirstSampleOff+8], 0)
	binary.BigEndian.PutUint32(dgram[testFirstSampleOff+8:testFirstSampleOff+12], dsIndex)
	return dgram
}

func compactSample(t *testing.T, inIf, outIf, dsIndex uint32) []byte {
	t.Helper()
	dgram := buildTestSFlowDatagramWithIfaces(t, buildTestIPv4UDPDatagram(), 8192, inIf, outIf)
	binary.BigEndian.PutUint32(dgram[testFirstSampleOff+4:testFirstSampleOff+8], dsIndex&0xFFFFFF)
	return dgram
}

const (
	testUplink  = 369098755
	testMX204   = 369098756
	testRackEth = 436210688
)

func TestSFlowDropsEgressCopyOfIngressSampledPacket(t *testing.T) {
	now := time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)
	ports := newSFlowIngressPorts()
	var m sflowMetrics

	rows := parseSFlowV5(expandedSample(t, testUplink, testMX204, testUplink), now, "sflow-default", nil, nil, &m, ports)
	if len(rows) != 1 {
		t.Fatalf("ingress sample rows=%d want 1", len(rows))
	}
	rows = parseSFlowV5(expandedSample(t, testUplink, testMX204, testMX204), now, "sflow-default", nil, nil, &m, ports)
	if len(rows) != 0 {
		t.Fatalf("egress copy rows=%d want 0", len(rows))
	}
	if m.ingressSamples.Load() != 1 || m.egressSamples.Load() != 1 || m.egressDropped.Load() != 1 {
		t.Fatalf("ingress=%d egress=%d dropped=%d want 1/1/1",
			m.ingressSamples.Load(), m.egressSamples.Load(), m.egressDropped.Load())
	}
}

func TestSFlowKeepsEgressWhenInputPortIsNotSampledOnIngress(t *testing.T) {
	now := time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)
	ports := newSFlowIngressPorts()
	var m sflowMetrics

	parseSFlowV5(expandedSample(t, testMX204, testRackEth, testMX204), now, "sflow-default", nil, nil, &m, ports)
	rows := parseSFlowV5(expandedSample(t, testRackEth, testUplink, testUplink), now, "sflow-default", nil, nil, &m, ports)
	if len(rows) != 1 {
		t.Fatalf("sole egress copy rows=%d want 1", len(rows))
	}
	if m.egressDropped.Load() != 0 {
		t.Fatalf("dropped=%d want 0", m.egressDropped.Load())
	}
}

func TestSFlowKeepsEgressWhenFilterDisabled(t *testing.T) {
	now := time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)
	var m sflowMetrics

	parseSFlowV5(expandedSample(t, testUplink, testMX204, testUplink), now, "sflow-default", nil, nil, &m, nil)
	rows := parseSFlowV5(expandedSample(t, testUplink, testMX204, testMX204), now, "sflow-default", nil, nil, &m, nil)
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1 with the filter off", len(rows))
	}
}

func TestSFlowCompactSampleSourceID(t *testing.T) {
	now := time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)
	ports := newSFlowIngressPorts()
	var m sflowMetrics

	parseSFlowV5(compactSample(t, 3013, 3025, 3013), now, "sflow-default", nil, nil, &m, ports)
	rows := parseSFlowV5(compactSample(t, 3013, 3025, 3025), now, "sflow-default", nil, nil, &m, ports)
	if len(rows) != 0 {
		t.Fatalf("compact egress copy rows=%d want 0", len(rows))
	}
	if m.egressDropped.Load() != 1 {
		t.Fatalf("dropped=%d want 1", m.egressDropped.Load())
	}
}

func TestSFlowUnmatchedDataSourceIsKept(t *testing.T) {
	now := time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)
	ports := newSFlowIngressPorts()
	var m sflowMetrics

	parseSFlowV5(expandedSample(t, testUplink, testMX204, testUplink), now, "sflow-default", nil, nil, &m, ports)
	rows := parseSFlowV5(expandedSample(t, testUplink, testMX204, 1<<31), now, "sflow-default", nil, nil, &m, ports)
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1 for a data source that is neither port", len(rows))
	}
	if m.egressSamples.Load() != 0 {
		t.Fatalf("egress=%d want 0", m.egressSamples.Load())
	}
}

func TestSFlowIngressPortsExpire(t *testing.T) {
	now := time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)
	ports := newSFlowIngressPorts()
	var sampler [16]byte
	ports.mark(sampler, testUplink, now)
	if !ports.samplesIngress(sampler, testUplink, now.Add(9*time.Minute)) {
		t.Fatal("port must still count as ingress-sampled after 9 minutes")
	}
	if ports.samplesIngress(sampler, testUplink, now.Add(11*time.Minute)) {
		t.Fatal("port must expire after the TTL")
	}
}

func TestSFlowSampleSideOf(t *testing.T) {
	cases := []struct {
		name                         string
		dsType, dsIndex, inIf, outIf uint32
		want                         sflowSampleSide
	}{
		{"ingress", 0, 10, 10, 20, sflowSideIngress},
		{"egress", 0, 20, 10, 20, sflowSideEgress},
		{"neither", 0, 30, 10, 20, sflowSideUnknown},
		{"vlan data source", 1, 20, 10, 20, sflowSideUnknown},
		{"no data source", 0, 0, 0, 20, sflowSideUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sflowSampleSideOf(tc.dsType, tc.dsIndex, tc.inIf, tc.outIf); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
