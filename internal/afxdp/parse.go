//go:build linux

package afxdp

// Ethernet + VLAN + L3/L4 parse aligned with bpf/xdp_flow.c.

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
	"xdpflowd/internal/netv9"
)

const (
	ethP8021Q  = 0x8100
	ethP8021AD = 0x88a8
	ethPIPv4   = 0x0800
	ethPIPv6   = 0x86dd
)

// TCPAcc matches tcp_acc in xdp_flow.c
type TCPAcc struct {
	Flags  uint8
	SynCnt uint32
	RstCnt uint32
	FinCnt uint32
}

// PktMeta is per-packet data for flow updates.
type PktMeta struct {
	Now      uint64
	PktLen   uint32
	WireLen  uint16
	TTL      uint8
	FragIncr uint8
	Tos      uint8
	Acc      TCPAcc
}

// be16p: two on-wire bytes as u16 the same way BPF stores __be16 in a uint16.
func be16p(b []byte) uint16 {
	_ = b[1]
	return uint16(b[0]) | uint16(b[1])<<8
}

// ParseIPFrame decodes an L2 frame to flow key + metadata. If not IPv4/6, ok=false, parseErr=false.
// If truncated, ok=false, parseErr=true.
func ParseIPFrame(frame []byte) (k netv9.FlowKey, meta PktMeta, ok, parseErr bool) {
	if len(frame) < 14 {
		return k, meta, false, true
	}
	mono, err := netv9.MonoNow()
	if err != nil {
		return k, meta, false, true
	}
	meta.Now = mono
	meta.PktLen = uint32(len(frame))
	wl := len(frame)
	if wl > 0xFFFF {
		wl = 0xFFFF
	}
	meta.WireLen = uint16(wl)
	off := 12
	et := binary.BigEndian.Uint16(frame[off : off+2])
	off = 14
	var vlanID uint16
	for et == ethP8021Q || et == ethP8021AD {
		if len(frame) < off+4 {
			return k, meta, false, true
		}
		tci := binary.BigEndian.Uint16(frame[off : off+2])
		vlanID = tci & 0x0FFF
		et = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}
	switch et {
	case ethPIPv4:
		if len(frame) < off+20 {
			return k, meta, false, true
		}
		ihl := int(frame[off]) & 0x0f
		ihl *= 4
		if ihl < 20 || len(frame) < off+ihl {
			return k, meta, false, true
		}
		ip := frame[off : off+ihl]
		fragOff := binary.BigEndian.Uint16(ip[6:8])
		if (fragOff&0x1fff) != 0 || (fragOff&0x2000) != 0 {
			meta.FragIncr = 1
		}
		ttl := ip[8]
		tos := ip[1]
		proto := ip[9]
		copy(k.SrcAddr[:4], frame[off+12:off+16])
		copy(k.DstAddr[:4], frame[off+16:off+20])
		k.VLANID = vlanID
		k.IPVersion = 4
		rest := frame[off+ihl:]
		acc, perr := parseL4v6(&k, rest, proto)
		if perr {
			return k, meta, false, true
		}
		meta.TTL = ttl
		meta.Tos = tos
		meta.Acc = acc
		return k, meta, true, false
	case ethPIPv6:
		if len(frame) < off+40 {
			return k, meta, false, true
		}
		ip6 := frame[off : off+40]
		copy(k.SrcAddr[:], ip6[8:24])
		copy(k.DstAddr[:], ip6[24:40])
		hlim := ip6[7]
		p := ip6[6]
		nh := frame[off+40:]
		sawFrag := false
		for i := 0; i < 6; i++ {
			if p == unix.IPPROTO_HOPOPTS || p == unix.IPPROTO_ROUTING || p == unix.IPPROTO_DSTOPTS {
				if len(nh) < 2 {
					return k, meta, false, true
				}
				hdrlen := (int(nh[1]) + 1) * 8
				if len(nh) < hdrlen {
					return k, meta, false, true
				}
				p = nh[0]
				nh = nh[hdrlen:]
				continue
			}
			if p == unix.IPPROTO_FRAGMENT {
				if len(nh) < 8 {
					return k, meta, false, true
				}
				sawFrag = true
				p = nh[0]
				nh = nh[8:]
				continue
			}
			break
		}
		if len(nh) < 1 {
			return k, meta, false, true
		}
		k.VLANID = vlanID
		k.IPVersion = 6
		if sawFrag {
			meta.FragIncr = 1
		}
		if p == unix.IPPROTO_ICMPV6 {
			if len(nh) < 4 {
				return k, meta, false, true
			}
			k.Proto = unix.IPPROTO_ICMPV6
			k.SrcPort = uint16(nh[0])<<8 | uint16(nh[1])
			k.DstPort = 0
			meta.TTL = hlim
			meta.Tos = 0
			return k, meta, true, false
		}
		acc, perr := parseL4v6(&k, nh, p)
		if perr {
			return k, meta, false, true
		}
		meta.TTL = hlim
		meta.Tos = 0
		meta.Acc = acc
		return k, meta, true, false
	default:
		return k, meta, false, false
	}
}

func parseL4v6(k *netv9.FlowKey, l4 []byte, proto uint8) (acc TCPAcc, parseErr bool) {
	k.Proto = proto
	switch proto {
	case unix.IPPROTO_TCP:
		if len(l4) < 20 {
			return acc, true
		}
		hlen := int(l4[12]>>4) * 4
		if hlen < 20 || len(l4) < hlen {
			return acc, true
		}
		flags := l4[13]
		k.SrcPort = be16p(l4[0:2])
		k.DstPort = be16p(l4[2:4])
		if flags&0x01 != 0 {
			acc.Flags |= 0x01
			acc.FinCnt = 1
		}
		if flags&0x02 != 0 {
			acc.Flags |= 0x02
			acc.SynCnt = 1
		}
		if flags&0x04 != 0 {
			acc.Flags |= 0x04
			acc.RstCnt = 1
		}
		if flags&0x08 != 0 {
			acc.Flags |= 0x08
		}
		if flags&0x10 != 0 {
			acc.Flags |= 0x10
		}
		if flags&0x20 != 0 {
			acc.Flags |= 0x20
		}
		return acc, false
	case unix.IPPROTO_UDP:
		if len(l4) < 8 {
			return acc, true
		}
		k.SrcPort = be16p(l4[0:2])
		k.DstPort = be16p(l4[2:4])
		return acc, false
	case unix.IPPROTO_ICMP:
		if len(l4) < 2 {
			return acc, true
		}
		k.SrcPort = uint16(l4[0])<<8 | uint16(l4[1])
		k.DstPort = 0
		return acc, false
	default:
		k.SrcPort = 0
		k.DstPort = 0
		return acc, false
	}
}
