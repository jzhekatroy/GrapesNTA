//go:build linux

package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket/afpacket"
	"golang.org/x/net/bpf"
)

// openRingCapture opens a TPACKET_V3 mmap RX ring (same mechanism as tcpdump/libpcap).
// Plain AF_PACKET read() drops most packets on busy mirror ports; the ring buffers bulk delivery.
func openRingCapture(ifname string) (*afpacket.TPacket, error) {
	const (
		frameSize = afpacket.DefaultFrameSize // 4096
		blockSize = afpacket.DefaultBlockSize // frameSize * 128 = 512 KiB per block
		numBlocks = 256                       // 256 * 512 KiB ≈ 128 MiB ring
	)
	h, err := afpacket.NewTPacket(
		afpacket.OptInterface(ifname),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		afpacket.OptFrameSize(frameSize),
		afpacket.OptBlockSize(blockSize),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptPollTimeout(250*time.Millisecond),
	)
	if err != nil {
		return nil, fmt.Errorf("afpacket TPACKET_V3 %q: %w", ifname, err)
	}
	filter, err := ipv4UDPDNSFilter()
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("assemble DNS BPF filter: %w", err)
	}
	if err := h.SetBPF(filter); err != nil {
		h.Close()
		return nil, fmt.Errorf("attach DNS BPF filter: %w", err)
	}
	if err := h.InitSocketStats(); err != nil {
		h.Close()
		return nil, fmt.Errorf("reset socket stats: %w", err)
	}
	return h, nil
}

func ipv4UDPDNSFilter() ([]bpf.RawInstruction, error) {
	// Ethernet filter for IPv4 UDP/53 with optional single 802.1Q/QinQ outer tag.
	// It keeps high-volume mirror traffic out of the TPACKET ring.
	const (
		ethPIPv4 = 0x0800
		ethPVLAN = 0x8100
		ethPQinQ = 0x88a8
		ipProtoUDP = 17
		dnsPort = 53
		snapLen = 65535
	)
	return bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},                                             // 0: EtherType
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ethPVLAN, SkipTrue: 11, SkipFalse: 0},     // 1: VLAN path
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ethPQinQ, SkipTrue: 10, SkipFalse: 0},     // 2: VLAN path
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ethPIPv4, SkipTrue: 0, SkipFalse: 21},     // 3: reject non-IPv4
		bpf.LoadAbsolute{Off: 23, Size: 1},                                             // 4: IPv4 protocol
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipProtoUDP, SkipTrue: 0, SkipFalse: 19},   // 5: reject non-UDP
		bpf.LoadAbsolute{Off: 20, Size: 2},                                             // 6: IPv4 frag flags/offset
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 17, SkipFalse: 0},     // 7: reject non-first fragments
		bpf.LoadMemShift{Off: 14},                                                     // 8: X = IPv4 header length
		bpf.LoadIndirect{Off: 14, Size: 2},                                             // 9: UDP source port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dnsPort, SkipTrue: 13, SkipFalse: 0},      // 10: accept src/53
		bpf.LoadIndirect{Off: 16, Size: 2},                                             // 11: UDP destination port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dnsPort, SkipTrue: 11, SkipFalse: 12},     // 12: accept dst/53 else reject
		bpf.LoadAbsolute{Off: 16, Size: 2},                                             // 13: inner EtherType
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ethPIPv4, SkipTrue: 0, SkipFalse: 10},     // 14: reject non-IPv4
		bpf.LoadAbsolute{Off: 27, Size: 1},                                             // 15: IPv4 protocol
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipProtoUDP, SkipTrue: 0, SkipFalse: 8},    // 16: reject non-UDP
		bpf.LoadAbsolute{Off: 24, Size: 2},                                             // 17: IPv4 frag flags/offset
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6, SkipFalse: 0},      // 18: reject non-first fragments
		bpf.LoadMemShift{Off: 18},                                                     // 19: X = IPv4 header length
		bpf.LoadIndirect{Off: 18, Size: 2},                                             // 20: UDP source port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dnsPort, SkipTrue: 2, SkipFalse: 0},       // 21: accept src/53
		bpf.LoadIndirect{Off: 20, Size: 2},                                             // 22: UDP destination port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dnsPort, SkipTrue: 0, SkipFalse: 1},       // 23: accept dst/53 else reject
		bpf.RetConstant{Val: snapLen},                                                 // 24: accept
		bpf.RetConstant{Val: 0},                                                       // 25: reject
	})
}
