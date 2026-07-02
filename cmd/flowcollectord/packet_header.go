package main

import (
	"encoding/binary"
)

const (
	ethTypeVLAN = 0x8100
	ethTypeQinQ = 0x88A8
	ethTypeIPv4 = 0x0800
	ethTypeIPv6 = 0x86DD
)

type parsedPacket struct {
	srcIP     [16]byte
	dstIP     [16]byte
	srcMAC    [6]byte
	dstMAC    [6]byte
	ipVersion uint8
	etype     uint32
	proto     uint32
	srcPort   uint32
	dstPort   uint32
	vlan      uint16
}

func parseEthernetHeader(b []byte) (parsedPacket, bool) {
	var out parsedPacket
	if len(b) < 14 {
		return out, false
	}
	// Ethernet II: destination MAC (0:6), source MAC (6:12), then EtherType.
	copy(out.dstMAC[:], b[0:6])
	copy(out.srcMAC[:], b[6:12])
	off := 12
	etype := binary.BigEndian.Uint16(b[off : off+2])
	off += 2

	for etype == ethTypeVLAN || etype == ethTypeQinQ {
		if len(b) < off+4 {
			return out, false
		}
		tci := binary.BigEndian.Uint16(b[off : off+2])
		if out.vlan == 0 {
			out.vlan = tci & 0x0FFF
		}
		off += 2
		etype = binary.BigEndian.Uint16(b[off : off+2])
		off += 2
	}

	out.etype = uint32(etype)
	switch etype {
	case ethTypeIPv4:
		return parseIPv4Header(b[off:], out)
	case ethTypeIPv6:
		return parseIPv6Header(b[off:], out)
	default:
		return out, false
	}
}

func parseIPv4Header(b []byte, out parsedPacket) (parsedPacket, bool) {
	if len(b) < 20 {
		return out, false
	}
	ihl := int(b[0]&0x0F) * 4
	if ihl < 20 || len(b) < ihl {
		return out, false
	}
	out.ipVersion = 4
	out.proto = uint32(b[9])
	copy(out.srcIP[:4], b[12:16])
	copy(out.dstIP[:4], b[16:20])
	return parseL4Ports(b[ihl:], out)
}

func parseIPv6Header(b []byte, out parsedPacket) (parsedPacket, bool) {
	if len(b) < 40 {
		return out, false
	}
	out.ipVersion = 6
	next := b[6]
	copy(out.srcIP[:], b[8:24])
	copy(out.dstIP[:], b[24:40])
	off := 40
	for {
		switch next {
		case 6, 17, 58: // TCP, UDP, ICMPv6
			out.proto = uint32(next)
			return parseL4Ports(b[off:], out)
		case 0, 43, 44, 60: // hop-by-hop, routing, fragment, destination
			if len(b) < off+2 {
				return out, false
			}
			next = b[off]
			hdrLen := int(b[off+1])*8 + 8
			if hdrLen < 8 || len(b) < off+hdrLen {
				return out, false
			}
			off += hdrLen
			continue
		default:
			out.proto = uint32(next)
			return out, true
		}
	}
}

func parseL4Ports(b []byte, out parsedPacket) (parsedPacket, bool) {
	switch out.proto {
	case 6, 17: // TCP, UDP
		if len(b) < 4 {
			return out, true
		}
		out.srcPort = uint32(binary.BigEndian.Uint16(b[0:2]))
		out.dstPort = uint32(binary.BigEndian.Uint16(b[2:4]))
	}
	return out, true
}
