package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// FlowRow is the production-shaped row for default.flows_raw (and internal spool).
// Column order matches INSERT in clickhouse_sink.go.
type FlowRow struct {
	Date             time.Time // partition key; usually derived from received time
	TimeInsertedNs   time.Time
	TimeReceivedNs   time.Time
	TimeFlowStartNs  time.Time
	SequenceNum      uint32
	SamplingRate     uint64
	SamplerAddress   [16]byte
	SrcAddr          [16]byte
	DstAddr          [16]byte
	SrcAS            uint32
	DstAS            uint32
	SrcASN           uint32
	DstASN           uint32
	Direction        string
	SrcKind          string
	DstKind          string
	SrcLabel         string
	DstLabel         string
	SrcOperator      string
	DstOperator      string
	SrcVLAN          uint16
	DstVLAN          uint16
	Etype            uint32
	Proto            uint32
	SrcPort          uint32
	DstPort          uint32
	Bytes            uint64
	Packets          uint64
}

type flowRowMapper struct {
	clock          ExportClock
	samplerAddress [16]byte
	sequence       uint32
	classifier     *trafficClassifier
}

func newFlowRowMapper(clock ExportClock, sampler [16]byte, seqBase uint32, classifier *trafficClassifier) flowRowMapper {
	return flowRowMapper{clock: clock, samplerAddress: sampler, sequence: seqBase, classifier: classifier}
}

// flowRowsFromKV converts BPF map entries to ClickHouse / spool rows using one shared
// received-at timestamp (wall) for the export batch.
func flowRowsFromKV(flows []flowKV, m flowRowMapper, receivedAt time.Time) []FlowRow {
	if len(flows) == 0 {
		return nil
	}
	ra := receivedAt.UTC()
	out := make([]FlowRow, 0, len(flows))
	for _, fv := range flows {
		out = append(out, flowRowFromKV(fv, m, ra))
	}
	return out
}

func flowRowFromKV(fv flowKV, m flowRowMapper, receivedAt time.Time) FlowRow {
	firstWall := m.clock.monoNsToWall(fv.v.FirstSeenNs)
	var srcClass endpointClass
	var dstClass endpointClass
	var direction string
	srcVLAN := fv.k.VLANID
	var dstVLAN uint16
	if m.classifier != nil {
		srcClass, dstClass, direction = m.classifier.classifyPair(fv.k.SrcAddr, fv.k.DstAddr, fv.k.IPVersion, srcVLAN, dstVLAN)
	}
	return FlowRow{
		Date:            receivedAt,
		TimeInsertedNs:  receivedAt,
		TimeReceivedNs:  receivedAt,
		TimeFlowStartNs: firstWall,
		SequenceNum:     m.sequence,
		SamplingRate:    1,
		SamplerAddress:  m.samplerAddress,
		SrcAddr:         fv.k.SrcAddr,
		DstAddr:         fv.k.DstAddr,
		SrcAS:           srcClass.ASN,
		DstAS:           dstClass.ASN,
		SrcASN:          srcClass.ASN,
		DstASN:          dstClass.ASN,
		Direction:       direction,
		SrcKind:         srcClass.Kind,
		DstKind:         dstClass.Kind,
		SrcLabel:        srcClass.Label,
		DstLabel:        dstClass.Label,
		SrcOperator:     srcClass.OperatorID,
		DstOperator:     dstClass.OperatorID,
		SrcVLAN:         srcVLAN,
		DstVLAN:         dstVLAN,
		Etype:           etherType(fv.k.IPVersion),
		Proto:           uint32(fv.k.Proto),
		SrcPort:         uint32(keyPortHost(fv.k.SrcPort)),
		DstPort:         uint32(keyPortHost(fv.k.DstPort)),
		Bytes:           fv.v.Bytes,
		Packets:         fv.v.Packets,
	}
}

// parseSamplerAddress sets 16-byte FixedString layout: IPv4 in first 4 bytes (rest zero);
// IPv6 uses full width.
func parseSamplerAddress(s string) ([16]byte, error) {
	var z [16]byte
	s = strings.TrimSpace(s)
	if s == "" {
		return z, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return z, fmt.Errorf("invalid -ch-sampler-addr %q", s)
	}
	if ip4 := ip.To4(); ip4 != nil {
		copy(z[:4], ip4)
		return z, nil
	}
	ip = ip.To16()
	copy(z[:], ip)
	return z, nil
}
