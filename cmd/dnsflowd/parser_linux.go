//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsFrameKind is a cheap L3/L4 class for port-53 frames. Only ipv4UDP is
// parsed into dns_log; the rest exist so we can measure capture blind spots.
type dnsFrameKind uint8

const (
	dnsFrameOther dnsFrameKind = iota
	dnsFrameIPv4UDP
	dnsFrameIPv6UDP
	dnsFrameIPv4TCP
	dnsFrameIPv6TCP
)

func (k dnsFrameKind) String() string {
	switch k {
	case dnsFrameIPv4UDP:
		return "ipv4_udp"
	case dnsFrameIPv6UDP:
		return "ipv6_udp"
	case dnsFrameIPv4TCP:
		return "ipv4_tcp"
	case dnsFrameIPv6TCP:
		return "ipv6_tcp"
	default:
		return "other"
	}
}

// ethPayloadOffset returns the offset of the L3 header and ethertype after
// Ethernet + optional single 802.1Q/QinQ tag.
func ethPayloadOffset(frame []byte) (off int, et uint16, ok bool) {
	if len(frame) < 14 {
		return 0, 0, false
	}
	off = 14
	et = binary.BigEndian.Uint16(frame[12:14])
	if et == 0x8100 || et == 0x88a8 {
		if len(frame) < off+4 {
			return 0, 0, false
		}
		et = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}
	return off, et, true
}

// classifyPort53Frame classifies a BPF-matched port-53 frame. For IPv4/UDP it
// also returns addresses, ports and DNS payload (same as parseIPv4UDPPayload).
// Other classes return kind only; payload is nil.
func classifyPort53Frame(frame []byte) (kind dnsFrameKind, srcIP, dstIP [16]byte, sport, dport uint16, payload []byte) {
	off, et, ok := ethPayloadOffset(frame)
	if !ok {
		return dnsFrameOther, srcIP, dstIP, 0, 0, nil
	}
	switch et {
	case 0x0800: // IPv4
		if len(frame) < off+20 {
			return dnsFrameOther, srcIP, dstIP, 0, 0, nil
		}
		ip := frame[off:]
		ihl := int(ip[0]&0xf) * 4
		if ihl < 20 || len(ip) < ihl {
			return dnsFrameOther, srcIP, dstIP, 0, 0, nil
		}
		proto := ip[9]
		switch proto {
		case 17: // UDP
			if len(ip) < ihl+8 {
				return dnsFrameOther, srcIP, dstIP, 0, 0, nil
			}
			copy(srcIP[:4], ip[12:16])
			copy(dstIP[:4], ip[16:20])
			udp := ip[ihl:]
			sport = binary.BigEndian.Uint16(udp[0:2])
			dport = binary.BigEndian.Uint16(udp[2:4])
			ulen := int(binary.BigEndian.Uint16(udp[4:6]))
			if ulen < 8 {
				return dnsFrameOther, srcIP, dstIP, sport, dport, nil
			}
			wantEnd := off + ihl + ulen
			if wantEnd > len(frame) {
				wantEnd = len(frame)
			}
			payload = frame[off+ihl+8 : wantEnd]
			return dnsFrameIPv4UDP, srcIP, dstIP, sport, dport, payload
		case 6: // TCP
			if len(ip) < ihl+4 {
				return dnsFrameOther, srcIP, dstIP, 0, 0, nil
			}
			tcp := ip[ihl:]
			sport = binary.BigEndian.Uint16(tcp[0:2])
			dport = binary.BigEndian.Uint16(tcp[2:4])
			return dnsFrameIPv4TCP, srcIP, dstIP, sport, dport, nil
		default:
			return dnsFrameOther, srcIP, dstIP, 0, 0, nil
		}
	case 0x86dd: // IPv6
		// Fixed 40-byte header only; extension headers count as other.
		if len(frame) < off+40 {
			return dnsFrameOther, srcIP, dstIP, 0, 0, nil
		}
		ip := frame[off:]
		next := ip[6]
		copy(srcIP[:], ip[8:24])
		copy(dstIP[:], ip[24:40])
		l4 := ip[40:]
		switch next {
		case 17: // UDP
			if len(l4) < 4 {
				return dnsFrameOther, srcIP, dstIP, 0, 0, nil
			}
			sport = binary.BigEndian.Uint16(l4[0:2])
			dport = binary.BigEndian.Uint16(l4[2:4])
			return dnsFrameIPv6UDP, srcIP, dstIP, sport, dport, nil
		case 6: // TCP
			if len(l4) < 4 {
				return dnsFrameOther, srcIP, dstIP, 0, 0, nil
			}
			sport = binary.BigEndian.Uint16(l4[0:2])
			dport = binary.BigEndian.Uint16(l4[2:4])
			return dnsFrameIPv6TCP, srcIP, dstIP, sport, dport, nil
		default:
			return dnsFrameOther, srcIP, dstIP, 0, 0, nil
		}
	default:
		return dnsFrameOther, srcIP, dstIP, 0, 0, nil
	}
}

// parseIPv4UDPPayload extracts IPv4 UDP payload from an Ethernet frame (optional one 802.1Q tag).
func parseIPv4UDPPayload(frame []byte) (srcIP, dstIP [16]byte, sport, dport uint16, payload []byte, ok bool) {
	kind, sip, dip, sp, dp, pay := classifyPort53Frame(frame)
	if kind != dnsFrameIPv4UDP || len(pay) == 0 {
		return
	}
	return sip, dip, sp, dp, pay, true
}

func u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// maxAnswerRRs caps DNS answer-section parsing to keep parseDNS responsive on
// malformed or oversized payloads (a single UDP DNS response with hundreds of
// RRs is already pathological).
const maxAnswerRRs = 256

func parseDNS(payload []byte, srcIP, dstIP [16]byte, sport, dport uint16, sampler [16]byte, now time.Time) (row DNSRow, err error) {
	defer func() {
		if r := recover(); r != nil {
			row = DNSRow{}
			err = fmt.Errorf("panic in parseDNS: %v (payload_len=%d)", r, len(payload))
		}
	}()

	var p dnsmessage.Parser
	h, err := p.Start(payload)
	if err != nil {
		return DNSRow{}, err
	}

	row = DNSRow{
		Ts:                 now.UTC(),
		SamplerAddress:     sampler,
		Transport:          "udp",
		TXID:               h.ID,
		RCode:              uint8(h.RCode),
		Truncated:          u8(h.Truncated),
		RecursionDesired:   u8(h.RecursionDesired),
		RecursionAvailable: u8(h.RecursionAvailable),
		RawSize:            uint16(len(payload)),
		QClass:             "IN",
	}
	if h.Response {
		row.IsResponse = 1
		row.ClientIP = dstIP
		row.ServerIP = srcIP
		row.ClientPort = dport
		row.ServerPort = sport
	} else {
		row.IsResponse = 0
		row.ClientIP = srcIP
		row.ServerIP = dstIP
		row.ClientPort = sport
		row.ServerPort = dport
	}

	q, err := p.Question()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return DNSRow{}, err
	}
	if err == nil {
		row.QueryName = strings.ToLower(q.Name.String())
		row.QType = q.Type.String()
		row.QClass = q.Class.String()
	}
	if err := p.SkipAllQuestions(); err != nil {
		return DNSRow{}, err
	}

	if !h.Response {
		row.AnswerCount = 0
		return row, nil
	}

	answerRRs := 0
answers:
	for i := 0; i < maxAnswerRRs; i++ {
		ah, ahErr := p.AnswerHeader()
		if ahErr == dnsmessage.ErrSectionDone {
			break answers
		}
		if ahErr != nil {
			break answers
		}
		answerRRs++

		switch ah.Type {
		case dnsmessage.TypeA:
			ar, rerr := p.AResource()
			if rerr != nil {
				break answers
			}
			var v [16]byte
			copy(v[:4], ar.A[:])
			row.AnswersA = append(row.AnswersA, v)
			row.AnswersATTLs = append(row.AnswersATTLs, ah.TTL)
			row.AnswerTTLs = append(row.AnswerTTLs, ah.TTL)
		case dnsmessage.TypeAAAA:
			ar, rerr := p.AAAAResource()
			if rerr != nil {
				break answers
			}
			var v [16]byte
			copy(v[:], ar.AAAA[:])
			row.AnswersAAAA = append(row.AnswersAAAA, v)
			row.AnswersAAAATTLs = append(row.AnswersAAAATTLs, ah.TTL)
			row.AnswerTTLs = append(row.AnswerTTLs, ah.TTL)
		case dnsmessage.TypeCNAME:
			cr, rerr := p.CNAMEResource()
			if rerr != nil {
				break answers
			}
			row.AnswersCNAME = append(row.AnswersCNAME, strings.ToLower(cr.CNAME.String()))
			row.AnswerTTLs = append(row.AnswerTTLs, ah.TTL)
		default:
			if serr := p.SkipAnswer(); serr != nil {
				break answers
			}
		}
	}

	row.AnswerCount = uint16(min(answerRRs, 65535))
	return row, nil
}

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
