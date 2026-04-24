// Package netv9 implements NetFlow v9 encoding and export (RFC 3954).
// Shared by xdpflowd (eBPF map) and afxdpflowd (userspace aggregation).
package netv9

// FlowKey matches struct flow_key in bpf/xdp_flow.c.
type FlowKey struct {
	SrcAddr   [16]byte
	DstAddr   [16]byte
	SrcPort   uint16
	DstPort   uint16
	VLANID    uint16
	Proto     uint8
	IPVersion uint8
}

// FlowValue matches struct flow_value in bpf/xdp_flow.c.
type FlowValue struct {
	Packets     uint64
	Bytes       uint64
	FirstSeenNs uint64
	LastSeenNs  uint64
	IngressIf   uint32
	RxQueue     uint32
	TCPSynCount uint32
	TCPRstCount uint32
	TCPFinCount uint32
	TCPFlagsOR  uint8
	Tos         uint8
	TTLMin      uint8
	TTLMax      uint8
	PktLenMin   uint16
	PktLenMax   uint16
	IPFragCount uint32
}
