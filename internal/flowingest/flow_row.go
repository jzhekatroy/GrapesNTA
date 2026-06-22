package flowingest

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// FlowRow is the production-shaped row for default.flows_raw (and internal spool).
// Column order matches INSERT in sink.go.
type FlowRow struct {
	Date             time.Time
	TimeInsertedNs   time.Time
	TimeReceivedNs   time.Time
	TimeFlowStartNs  time.Time
	SequenceNum      uint32
	SamplingRate     uint64
	SamplerAddress   [16]byte
	SourceID         string
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
	SrcAttachmentKind     string
	DstAttachmentKind     string
	SrcAttachmentBoundary string
	DstAttachmentBoundary string
	SrcAttachmentLabel    string
	DstAttachmentLabel    string
	SrcAttachmentOperator string
	DstAttachmentOperator string
	SrcEndpointScope      string
	DstEndpointScope      string
	SrcEndpointSource     string
	DstEndpointSource     string
	SrcNetworkName        string
	DstNetworkName        string
	SrcNetworkRole        string
	DstNetworkRole        string
	SrcRole               string
	DstRole               string
	SrcEntity             string
	DstEntity             string
	SrcVLAN          uint16
	DstVLAN          uint16
	Etype            uint32
	Proto            uint32
	SrcPort          uint32
	DstPort          uint32
	Bytes            uint64
	Packets          uint64
}

// SumFlowRows returns cumulative packet/byte counters for already materialized
// flow rows. These are the comparable units for ClickHouse completeness checks.
func SumFlowRows(rows []FlowRow) (packets, bytes uint64) {
	for i := range rows {
		packets += rows[i].Packets
		bytes += rows[i].Bytes
	}
	return packets, bytes
}

// ApplyEndpointClasses copies classifier output into enrichment columns.
func ApplyEndpointClasses(r *FlowRow, src, dst EndpointClass, direction string) {
	r.SrcAS = src.ASN
	r.DstAS = dst.ASN
	r.SrcASN = src.ASN
	r.DstASN = dst.ASN
	r.Direction = direction
	r.SrcKind = src.Scope
	r.DstKind = dst.Scope
	r.SrcLabel = src.Label
	r.DstLabel = dst.Label
	r.SrcOperator = src.OperatorID
	r.DstOperator = dst.OperatorID
	r.SrcAttachmentKind = src.Attachment.Kind
	r.DstAttachmentKind = dst.Attachment.Kind
	r.SrcAttachmentBoundary = src.Attachment.Boundary
	r.DstAttachmentBoundary = dst.Attachment.Boundary
	r.SrcAttachmentLabel = src.Attachment.Label
	r.DstAttachmentLabel = dst.Attachment.Label
	r.SrcAttachmentOperator = src.Attachment.OperatorID
	r.DstAttachmentOperator = dst.Attachment.OperatorID
	r.SrcEndpointScope = src.Scope
	r.DstEndpointScope = dst.Scope
	r.SrcEndpointSource = src.Source
	r.DstEndpointSource = dst.Source
	r.SrcNetworkName = src.NetworkName
	r.DstNetworkName = dst.NetworkName
	r.SrcNetworkRole = src.NetworkRole
	r.DstNetworkRole = dst.NetworkRole
	r.SrcRole = src.Role
	r.DstRole = dst.Role
	r.SrcEntity = src.Entity
	r.DstEntity = dst.Entity
}

// ParseSamplerAddress sets 16-byte FixedString layout: IPv4 in first 4 bytes (rest zero);
// IPv6 uses full width.
func ParseSamplerAddress(s string) ([16]byte, error) {
	var z [16]byte
	s = strings.TrimSpace(s)
	if s == "" {
		return z, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return z, fmt.Errorf("invalid sampler address %q", s)
	}
	if ip4 := ip.To4(); ip4 != nil {
		copy(z[:4], ip4)
		return z, nil
	}
	ip = ip.To16()
	copy(z[:], ip)
	return z, nil
}

// IPVersionFromEtype returns 4 or 6 for IPv4/IPv6 ethertypes.
func IPVersionFromEtype(etype uint32) uint8 {
	if etype == 0x86DD {
		return 6
	}
	return 4
}
