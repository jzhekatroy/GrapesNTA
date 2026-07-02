package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func buildTestIPv4UDPDatagram() []byte {
	// Ethernet + IPv4 + UDP: 10.0.0.1:12345 -> 10.0.0.2:53
	eth := make([]byte, 14+20+8)
	copy(eth[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	copy(eth[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	binary.BigEndian.PutUint16(eth[12:14], ethTypeIPv4)
	ip := eth[14:]
	ip[0] = 0x45
	ip[9] = 17
	copy(ip[12:16], net.ParseIP("10.0.0.1").To4())
	copy(ip[16:20], net.ParseIP("10.0.0.2").To4())
	udp := eth[34:]
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	return eth
}

func buildTestSFlowDatagram(t *testing.T, frame []byte, samplingRate uint32) []byte {
	t.Helper()
	rawRecord := make([]byte, 16+len(frame))
	binary.BigEndian.PutUint32(rawRecord[0:4], sflowHeaderEthernet)
	binary.BigEndian.PutUint32(rawRecord[4:8], uint32(len(frame)))
	binary.BigEndian.PutUint32(rawRecord[8:12], 0)
	binary.BigEndian.PutUint32(rawRecord[12:16], uint32(len(frame)))
	copy(rawRecord[16:], frame)
	pad := (4 - (len(rawRecord) % 4)) % 4
	if pad > 0 {
		rawRecord = append(rawRecord, make([]byte, pad)...)
	}

	flowSample := make([]byte, 32+8+len(rawRecord))
	binary.BigEndian.PutUint32(flowSample[8:12], samplingRate)
	binary.BigEndian.PutUint32(flowSample[28:32], 1)
	binary.BigEndian.PutUint32(flowSample[32:36], sflowFlowRawHeader)
	binary.BigEndian.PutUint32(flowSample[36:40], uint32(len(rawRecord)))
	copy(flowSample[40:], rawRecord)

	dgram := make([]byte, 0, 64+len(flowSample))
	putU32 := func(v uint32) {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], v)
		dgram = append(dgram, buf[:]...)
	}
	putU32(sflowVersion)
	putU32(sflowAgentIPv4)
	dgram = append(dgram, net.ParseIP("192.0.2.1").To4()...)
	putU32(0)    // sub_agent_id
	putU32(100)  // sequence
	putU32(1000) // uptime
	putU32(1)    // num_samples
	putU32(sflowSampleFlow)
	putU32(uint32(len(flowSample)))
	dgram = append(dgram, flowSample...)
	return dgram
}

func buildTestExpandedSFlowDatagram(t *testing.T, frame []byte, samplingRate uint32) []byte {
	t.Helper()
	rawRecord := make([]byte, 16+len(frame))
	binary.BigEndian.PutUint32(rawRecord[0:4], sflowHeaderEthernet)
	binary.BigEndian.PutUint32(rawRecord[4:8], uint32(len(frame)))
	binary.BigEndian.PutUint32(rawRecord[8:12], 0)
	binary.BigEndian.PutUint32(rawRecord[12:16], uint32(len(frame)))
	copy(rawRecord[16:], frame)
	pad := (4 - (len(rawRecord) % 4)) % 4
	if pad > 0 {
		rawRecord = append(rawRecord, make([]byte, pad)...)
	}

	flowSample := make([]byte, 44+8+len(rawRecord))
	binary.BigEndian.PutUint32(flowSample[12:16], samplingRate)
	binary.BigEndian.PutUint32(flowSample[40:44], 1)
	binary.BigEndian.PutUint32(flowSample[44:48], sflowFlowRawHeader)
	binary.BigEndian.PutUint32(flowSample[48:52], uint32(len(rawRecord)))
	copy(flowSample[52:], rawRecord)

	dgram := make([]byte, 0, 64+len(flowSample))
	putU32 := func(v uint32) {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], v)
		dgram = append(dgram, buf[:]...)
	}
	putU32(sflowVersion)
	putU32(sflowAgentIPv4)
	dgram = append(dgram, net.ParseIP("192.0.2.1").To4()...)
	putU32(0)
	putU32(100)
	putU32(1000)
	putU32(1)
	putU32(sflowSampleFlowExp)
	putU32(uint32(len(flowSample)))
	dgram = append(dgram, flowSample...)
	return dgram
}

func TestParseSFlowV5PreScale(t *testing.T) {
	frame := buildTestIPv4UDPDatagram()
	dgram := buildTestSFlowDatagram(t, frame, 2000)
	var seq uint32
	var m sflowMetrics
	now := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	rows := parseSFlowV5(dgram, now, "sflow-default", nil, &seq, &m)
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1 metrics=%+v", len(rows), m)
	}
	r := rows[0]
	if r.SourceID != "sflow-default" {
		t.Fatalf("source_id=%q", r.SourceID)
	}
	if r.SamplingRate != 2000 {
		t.Fatalf("sampling_rate=%d", r.SamplingRate)
	}
	if r.Packets != 2000 {
		t.Fatalf("packets=%d", r.Packets)
	}
	wantBytes := uint64(len(frame)) * 2000
	if r.Bytes != wantBytes {
		t.Fatalf("bytes=%d want %d", r.Bytes, wantBytes)
	}
	if r.SrcPort != 12345 || r.DstPort != 53 {
		t.Fatalf("ports=%d->%d", r.SrcPort, r.DstPort)
	}
	if r.Proto != 17 {
		t.Fatalf("proto=%d", r.Proto)
	}
	if r.SrcMAC != ([6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) ||
		r.DstMAC != ([6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Fatalf("mac src=%x dst=%x", r.SrcMAC, r.DstMAC)
	}
}

func TestParseSFlowV5ExpandedPreScale(t *testing.T) {
	frame := buildTestIPv4UDPDatagram()
	dgram := buildTestExpandedSFlowDatagram(t, frame, 4000)
	var seq uint32
	var m sflowMetrics
	now := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	rows := parseSFlowV5(dgram, now, "sflow-default", nil, &seq, &m)
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1 metrics=%+v", len(rows), m)
	}
	r := rows[0]
	if r.SamplingRate != 4000 {
		t.Fatalf("sampling_rate=%d", r.SamplingRate)
	}
	if r.Packets != 4000 {
		t.Fatalf("packets=%d", r.Packets)
	}
	wantBytes := uint64(len(frame)) * 4000
	if r.Bytes != wantBytes {
		t.Fatalf("bytes=%d want %d", r.Bytes, wantBytes)
	}
	if r.SrcPort != 12345 || r.DstPort != 53 {
		t.Fatalf("ports=%d->%d", r.SrcPort, r.DstPort)
	}
}

func TestParseEthernetHeaderVLAN(t *testing.T) {
	frame := buildTestIPv4UDPDatagram()
	tagged := make([]byte, 0, len(frame)+4)
	tagged = append(tagged, frame[:12]...)
	var vlanHdr [4]byte
	binary.BigEndian.PutUint16(vlanHdr[0:2], ethTypeVLAN)
	binary.BigEndian.PutUint16(vlanHdr[2:4], (100&0x0FFF)|0x1000)
	tagged = append(tagged, vlanHdr[:]...)
	tagged = append(tagged, frame[12:]...)

	pkt, ok := parseEthernetHeader(tagged)
	if !ok {
		t.Fatal("parse failed")
	}
	if pkt.vlan != 100 {
		t.Fatalf("vlan=%d", pkt.vlan)
	}
	if pkt.dstMAC != ([6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) ||
		pkt.srcMAC != ([6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Fatalf("mac src=%x dst=%x", pkt.srcMAC, pkt.dstMAC)
	}
}

func TestParseSFlowSkipsCounterSample(t *testing.T) {
	counterBody := make([]byte, 16)
	dgram := make([]byte, 0, 128)
	put := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		dgram = append(dgram, b[:]...)
	}
	put(sflowVersion)
	put(sflowAgentIPv4)
	dgram = append(dgram, net.ParseIP("192.0.2.2").To4()...)
	put(0)
	put(1)
	put(1)
	put(1)
	put(sflowSampleCounter)
	put(uint32(len(counterBody)))
	dgram = append(dgram, counterBody...)

	var m sflowMetrics
	rows := parseSFlowV5(dgram, time.Now(), "sflow-default", nil, nil, &m)
	if len(rows) != 0 {
		t.Fatalf("rows=%d want 0", len(rows))
	}
	if got := m.counterSkipped.Load(); got != 1 {
		t.Fatalf("counterSkipped=%d", got)
	}
}
