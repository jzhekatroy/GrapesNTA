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

// parseIPv4UDPPayload extracts IPv4 UDP payload from an Ethernet frame (optional one 802.1Q tag).
func parseIPv4UDPPayload(frame []byte) (srcIP, dstIP [16]byte, sport, dport uint16, payload []byte, ok bool) {
	if len(frame) < 14 {
		return
	}
	off := 14
	et := binary.BigEndian.Uint16(frame[12:14])
	if et == 0x8100 || et == 0x88a8 {
		if len(frame) < off+4 {
			return
		}
		et = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}
	if et != 0x0800 {
		return
	}
	if len(frame) < off+20 {
		return
	}
	ip := frame[off:]
	ihl := int(ip[0]&0xf) * 4
	if ihl < 20 || len(ip) < ihl+8 {
		return
	}
	if ip[9] != 17 { // UDP
		return
	}
	copy(srcIP[:4], ip[12:16])
	copy(dstIP[:4], ip[16:20])
	udp := ip[ihl:]
	sport = binary.BigEndian.Uint16(udp[0:2])
	dport = binary.BigEndian.Uint16(udp[2:4])
	ulen := int(binary.BigEndian.Uint16(udp[4:6]))
	if ulen < 8 {
		return
	}
	wantEnd := off + ihl + ulen
	if wantEnd > len(frame) {
		wantEnd = len(frame)
	}
	payload = frame[off+ihl+8 : wantEnd]
	ok = true
	return
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
