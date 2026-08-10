package main

import (
	"time"

	"xdpflowd/internal/flowingest"
)

type flowRowMapper struct {
	clock          ExportClock
	samplerAddress [16]byte
	sequence       uint32
	sourceID       string
	classifier     *flowingest.TrafficClassifier
}

func newFlowRowMapper(clock ExportClock, sampler [16]byte, seqBase uint32, sourceID string, classifier *flowingest.TrafficClassifier) flowRowMapper {
	return flowRowMapper{clock: clock, samplerAddress: sampler, sequence: seqBase, sourceID: sourceID, classifier: classifier}
}

func flowRowsFromKV(flows []flowKV, m flowRowMapper, receivedAt time.Time) []flowingest.FlowRow {
	if len(flows) == 0 {
		return nil
	}
	ra := receivedAt.UTC()
	out := make([]flowingest.FlowRow, 0, len(flows))
	for _, fv := range flows {
		out = append(out, flowRowFromKV(fv, m, ra))
	}
	return out
}

func flowRowFromKV(fv flowKV, m flowRowMapper, receivedAt time.Time) flowingest.FlowRow {
	firstWall := m.clock.monoNsToWall(fv.v.FirstSeenNs)
	srcVLAN := fv.k.VLANID
	var dstVLAN uint16

	row := flowingest.FlowRow{
		Date:            receivedAt,
		TimeInsertedNs:  receivedAt,
		TimeReceivedNs:  receivedAt,
		TimeFlowStartNs: firstWall,
		SequenceNum:     m.sequence,
		SamplingRate:    1,
		SamplerAddress:  m.samplerAddress,
		SourceID:        m.sourceID,
		SrcAddr:         fv.k.SrcAddr,
		DstAddr:         fv.k.DstAddr,
		SrcVLAN:         srcVLAN,
		DstVLAN:         dstVLAN,
		Etype:           flowingest.EtherType(fv.k.IPVersion),
		Proto:           uint32(fv.k.Proto),
		SrcPort:         uint32(keyPortHost(fv.k.SrcPort)),
		DstPort:         uint32(keyPortHost(fv.k.DstPort)),
		Bytes:           fv.v.Bytes,
		Packets:         fv.v.Packets,
		SrcMAC:          fv.k.SrcMAC,
		DstMAC:          fv.k.DstMAC,
		TCPFlags:        fv.v.TCPFlagsOR,
		IPTos:           fv.v.Tos,
		IPTTL:           fv.v.TTLMin,
	}
	if m.classifier != nil {
		srcClass, dstClass, direction := m.classifier.ClassifyPair(
			fv.k.SrcAddr, fv.k.DstAddr, fv.k.IPVersion, srcVLAN, dstVLAN,
		)
		// The mirror path carries no ifIndex, so port mode always resolves to
		// unknown here instead of mixing two direction models in one column.
		if d, ok := m.classifier.PortDirection(m.samplerAddress, row.InIf, row.OutIf); ok {
			direction = d
		}
		flowingest.ApplyEndpointClasses(&row, srcClass, dstClass, direction)
		m.classifier.AttachClients(&row)
	}
	return row
}
