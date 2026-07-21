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
	ttl       uint8 // IPv4 TTL / IPv6 hop limit
	tos       uint8 // IPv4 DSCP+ECN / IPv6 traffic class
	tcpFlags  uint8 // TCP flags byte (FIN..CWR); zero for non-TCP
}

// ethParseKind distinguishes IP flows from expected L2 non-IP (ARP, etc.).
type ethParseKind uint8

const (
	ethParseOK ethParseKind = iota
	ethParseNonIP
	ethParseError
)

func parseEthernetHeader(b []byte) (parsedPacket, ethParseKind) {
	var out parsedPacket
	if len(b) < 14 {
		return out, ethParseError
	}
	// Ethernet II: destination MAC (0:6), source MAC (6:12), then EtherType.
	copy(out.dstMAC[:], b[0:6])
	copy(out.srcMAC[:], b[6:12])
	off := 12
	etype := binary.BigEndian.Uint16(b[off : off+2])
	off += 2

	for etype == ethTypeVLAN || etype == ethTypeQinQ {
		if len(b) < off+4 {
			return out, ethParseError
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
		pkt, ok := parseIPv4Header(b[off:], out)
		if !ok {
			return pkt, ethParseError
		}
		return pkt, ethParseOK
	case ethTypeIPv6:
		pkt, ok := parseIPv6Header(b[off:], out)
		if !ok {
			return pkt, ethParseError
		}
		return pkt, ethParseOK
	default:
		// ARP and other L2: expected on switch sFlow, not a parse failure.
		return out, ethParseNonIP
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
	out.tos = b[1]
	out.ttl = b[8]
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
	// Traffic class spans the low nibble of byte 0 and high nibble of byte 1.
	out.tos = uint8((binary.BigEndian.Uint16(b[0:2]) >> 4) & 0xFF)
	next := b[6]
	out.ttl = b[7] // hop limit
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
	case 6: // TCP
		if len(b) < 4 {
			return out, true
		}
		out.srcPort = uint32(binary.BigEndian.Uint16(b[0:2]))
		out.dstPort = uint32(binary.BigEndian.Uint16(b[2:4]))
		if len(b) >= 14 {
			out.tcpFlags = b[13] // flags byte: FIN,SYN,RST,PSH,ACK,URG,ECE,CWR
		}
	case 17: // UDP
		if len(b) < 4 {
			return out, true
		}
		out.srcPort = uint32(binary.BigEndian.Uint16(b[0:2]))
		out.dstPort = uint32(binary.BigEndian.Uint16(b[2:4]))
	}
	return out, true
}
