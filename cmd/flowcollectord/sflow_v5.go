package main

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"xdpflowd/internal/flowingest"
)

const (
	sflowVersion         = 5
	sflowAgentIPv4       = 1
	sflowAgentIPv6       = 2
	sflowSampleFlow      = 1
	sflowSampleCounter   = 2
	sflowSampleFlowExp   = 3
	sflowSampleCounterExp = 4
	sflowFlowRawHeader   = 1
	sflowHeaderEthernet  = 1

	maxSFlowSamples = 4096
	maxSFlowRecords = 4096
)

type sflowMetrics struct {
	datagrams       atomic.Uint64
	flowSamples     atomic.Uint64
	counterSkipped  atomic.Uint64
	recordsParsed   atomic.Uint64
	parseErrors     atomic.Uint64
	unknownSamples  atomic.Uint64
	udpQueueDrops   atomic.Uint64
}

func parseSFlowV5(
	b []byte,
	receivedAt time.Time,
	sourceID string,
	classifier *flowingest.TrafficClassifier,
	seq *uint32,
	m *sflowMetrics,
) []flowingest.FlowRow {
	if m != nil {
		m.datagrams.Add(1)
	}
	if len(b) < 28 {
		if m != nil {
			m.parseErrors.Add(1)
		}
		return nil
	}
	if binary.BigEndian.Uint32(b[0:4]) != sflowVersion {
		if m != nil {
			m.parseErrors.Add(1)
		}
		return nil
	}

	agentType := binary.BigEndian.Uint32(b[4:8])
	var sampler [16]byte
	off := 8
	switch agentType {
	case sflowAgentIPv4:
		if len(b) < off+4 {
			if m != nil {
				m.parseErrors.Add(1)
			}
			return nil
		}
		copy(sampler[:4], b[off:off+4])
		off += 4
	case sflowAgentIPv6:
		if len(b) < off+16 {
			if m != nil {
				m.parseErrors.Add(1)
			}
			return nil
		}
		copy(sampler[:], b[off:off+16])
		off += 16
	default:
		if m != nil {
			m.parseErrors.Add(1)
		}
		return nil
	}

	if len(b) < off+12 {
		if m != nil {
			m.parseErrors.Add(1)
		}
		return nil
	}
	// sub_agent_id, datagram_sequence, uptime
	off += 12
	numSamples := binary.BigEndian.Uint32(b[off : off+4])
	off += 4

	if numSamples > maxSFlowSamples {
		if m != nil {
			m.parseErrors.Add(1)
		}
		return nil
	}

	rows := make([]flowingest.FlowRow, 0, boundedCap(numSamples, maxSFlowSamples))
	for i := uint32(0); i < numSamples; i++ {
		if len(b) < off+8 {
			if m != nil {
				m.parseErrors.Add(1)
			}
			break
		}
		sampleType := binary.BigEndian.Uint32(b[off : off+4])
		sampleLen := int(binary.BigEndian.Uint32(b[off+4 : off+8]))
		off += 8
		if sampleLen < 0 || len(b) < off+sampleLen {
			if m != nil {
				m.parseErrors.Add(1)
			}
			break
		}
		sampleBody := b[off : off+sampleLen]
		off += sampleLen

		format := sampleType & 0xFFF
		switch format {
		case sflowSampleFlow:
			if m != nil {
				m.flowSamples.Add(1)
			}
			rows = append(rows, parseFlowSample(sampleBody, false, receivedAt, sourceID, sampler, classifier, seq, m)...)
		case sflowSampleFlowExp:
			if m != nil {
				m.flowSamples.Add(1)
			}
			rows = append(rows, parseFlowSample(sampleBody, true, receivedAt, sourceID, sampler, classifier, seq, m)...)
		case sflowSampleCounter, sflowSampleCounterExp:
			if m != nil {
				m.counterSkipped.Add(1)
			}
		default:
			if m != nil {
				m.unknownSamples.Add(1)
			}
		}
	}
	return rows
}

func parseFlowSample(
	b []byte,
	expanded bool,
	receivedAt time.Time,
	sourceID string,
	sampler [16]byte,
	classifier *flowingest.TrafficClassifier,
	seq *uint32,
	m *sflowMetrics,
) []flowingest.FlowRow {
	minLen := 32
	if expanded {
		minLen = 44
	}
	if len(b) < minLen {
		if m != nil {
			m.parseErrors.Add(1)
		}
		return nil
	}

	var samplingRate uint64
	var numRecords uint32
	var off int
	if expanded {
		// expanded flow sample:
		// sequence_number, source_id_type, source_id_index, sampling_rate,
		// sample_pool, drops, input_format, input_value, output_format,
		// output_value, records_count
		samplingRate = uint64(binary.BigEndian.Uint32(b[12:16]))
		numRecords = binary.BigEndian.Uint32(b[40:44])
		off = 44
	} else {
		// flow sample:
		// sequence_number, source_id, sampling_rate, sample_pool, drops,
		// input, output, records_count
		samplingRate = uint64(binary.BigEndian.Uint32(b[8:12]))
		numRecords = binary.BigEndian.Uint32(b[28:32])
		off = 32
	}
	if samplingRate == 0 {
		samplingRate = 1
	}
	if numRecords > maxSFlowRecords {
		if m != nil {
			m.parseErrors.Add(1)
		}
		return nil
	}

	rows := make([]flowingest.FlowRow, 0, boundedCap(numRecords, maxSFlowRecords))
	for i := uint32(0); i < numRecords; i++ {
		if len(b) < off+8 {
			if m != nil {
				m.parseErrors.Add(1)
			}
			break
		}
		recordType := binary.BigEndian.Uint32(b[off : off+4])
		recordLen := int(binary.BigEndian.Uint32(b[off+4 : off+8]))
		off += 8
		if recordLen < 0 || len(b) < off+recordLen {
			if m != nil {
				m.parseErrors.Add(1)
			}
			break
		}
		recordBody := b[off : off+recordLen]
		off += recordLen

		format := recordType & 0xFFF
		if format != sflowFlowRawHeader {
			continue
		}
		row, ok := flowRowFromRawHeader(recordBody, receivedAt, sourceID, sampler, samplingRate, classifier, seq)
		if !ok {
			if m != nil {
				m.parseErrors.Add(1)
			}
			continue
		}
		if m != nil {
			m.recordsParsed.Add(1)
		}
		rows = append(rows, row)
	}
	return rows
}

func boundedCap(n uint32, max int) int {
	if n > uint32(max) {
		return max
	}
	return int(n)
}

func flowRowFromRawHeader(
	b []byte,
	receivedAt time.Time,
	sourceID string,
	sampler [16]byte,
	samplingRate uint64,
	classifier *flowingest.TrafficClassifier,
	seq *uint32,
) (flowingest.FlowRow, bool) {
	if len(b) < 16 {
		return flowingest.FlowRow{}, false
	}
	headerProtocol := binary.BigEndian.Uint32(b[0:4])
	if headerProtocol != sflowHeaderEthernet {
		return flowingest.FlowRow{}, false
	}
	frameLength := binary.BigEndian.Uint32(b[4:8])
	// stripped := binary.BigEndian.Uint32(b[8:12])
	headerLength := binary.BigEndian.Uint32(b[12:16])
	if headerLength == 0 || len(b) < 16+int(headerLength) {
		return flowingest.FlowRow{}, false
	}
	headerBytes := b[16 : 16+headerLength]
	pkt, ok := parseEthernetHeader(headerBytes)
	if !ok {
		return flowingest.FlowRow{}, false
	}

	var rowSeq uint32
	if seq != nil {
		*seq++
		rowSeq = *seq
	}

	row := flowingest.FlowRow{
		Date:            receivedAt,
		TimeInsertedNs:  receivedAt,
		TimeReceivedNs:  receivedAt,
		TimeFlowStartNs: receivedAt,
		SequenceNum:     rowSeq,
		SamplingRate:    samplingRate,
		SamplerAddress:  sampler,
		SourceID:        sourceID,
		SrcAddr:         pkt.srcIP,
		DstAddr:         pkt.dstIP,
		SrcVLAN:         pkt.vlan,
		Etype:           pkt.etype,
		Proto:           pkt.proto,
		SrcPort:         pkt.srcPort,
		DstPort:         pkt.dstPort,
		Bytes:           uint64(frameLength) * samplingRate,
		Packets:         samplingRate,
	}
	if classifier != nil {
		srcClass, dstClass, direction := classifier.ClassifyPair(
			pkt.srcIP, pkt.dstIP, pkt.ipVersion, pkt.vlan, 0,
		)
		flowingest.ApplyEndpointClasses(&row, srcClass, dstClass, direction)
	}
	return row, true
}

func agentAddressFromIP(ip net.IP) ([16]byte, bool) {
	var out [16]byte
	if ip4 := ip.To4(); ip4 != nil {
		copy(out[:4], ip4)
		return out, true
	}
	ip = ip.To16()
	if ip == nil {
		return out, false
	}
	copy(out[:], ip)
	return out, true
}
