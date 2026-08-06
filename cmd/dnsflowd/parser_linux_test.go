//go:build linux

package main

import (
	"encoding/binary"
	"testing"
)

func TestParseIPv4UDPPayload(t *testing.T) {
	frame := make([]byte, 14+20+8+4)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45 // v4, IHL 5
	ip[9] = 17   // UDP
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	udp := frame[34:]
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+4))
	copy(udp[8:], []byte{1, 2, 3, 4})

	sip, dip, sp, dp, pay, ok := parseIPv4UDPPayload(frame)
	if !ok {
		t.Fatal("expected ok")
	}
	if sp != 12345 || dp != 53 {
		t.Fatalf("ports %d %d", sp, dp)
	}
	if pay[0] != 1 || pay[3] != 4 {
		t.Fatalf("payload %v", pay)
	}
	var expS, expD [16]byte
	copy(expS[:4], []byte{10, 0, 0, 1})
	copy(expD[:4], []byte{10, 0, 0, 2})
	if sip != expS || dip != expD {
		t.Fatalf("ip mismatch")
	}
}

func TestClassifyPort53Frame(t *testing.T) {
	mkIPv4 := func(proto byte, sport, dport uint16, payloadLen int) []byte {
		frame := make([]byte, 14+20+8+payloadLen)
		if proto == 6 {
			frame = make([]byte, 14+20+20) // TCP header, no payload needed
		}
		binary.BigEndian.PutUint16(frame[12:14], 0x0800)
		ip := frame[14:]
		ip[0] = 0x45
		ip[9] = proto
		copy(ip[12:16], []byte{10, 0, 0, 1})
		copy(ip[16:20], []byte{10, 0, 0, 2})
		l4 := frame[34:]
		binary.BigEndian.PutUint16(l4[0:2], sport)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		if proto == 17 {
			binary.BigEndian.PutUint16(l4[4:6], uint16(8+payloadLen))
			for i := 0; i < payloadLen; i++ {
				l4[8+i] = byte(i + 1)
			}
		}
		return frame
	}
	mkIPv6 := func(next byte, sport, dport uint16) []byte {
		frame := make([]byte, 14+40+8)
		binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
		ip := frame[14:]
		ip[0] = 0x60
		ip[6] = next
		copy(ip[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		copy(ip[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
		l4 := frame[54:]
		binary.BigEndian.PutUint16(l4[0:2], sport)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		return frame
	}

	t.Run("ipv4_udp", func(t *testing.T) {
		kind, _, _, sp, dp, pay := classifyPort53Frame(mkIPv4(17, 12345, 53, 4))
		if kind != dnsFrameIPv4UDP || sp != 12345 || dp != 53 || len(pay) != 4 {
			t.Fatalf("got kind=%s sp=%d dp=%d pay=%d", kind, sp, dp, len(pay))
		}
	})
	t.Run("ipv4_tcp", func(t *testing.T) {
		kind, _, _, sp, dp, pay := classifyPort53Frame(mkIPv4(6, 9999, 53, 0))
		if kind != dnsFrameIPv4TCP || sp != 9999 || dp != 53 || pay != nil {
			t.Fatalf("got kind=%s sp=%d dp=%d pay=%v", kind, sp, dp, pay)
		}
	})
	t.Run("ipv6_udp", func(t *testing.T) {
		kind, _, _, sp, dp, pay := classifyPort53Frame(mkIPv6(17, 53, 40000))
		if kind != dnsFrameIPv6UDP || sp != 53 || dp != 40000 || pay != nil {
			t.Fatalf("got kind=%s sp=%d dp=%d pay=%v", kind, sp, dp, pay)
		}
	})
	t.Run("ipv6_tcp", func(t *testing.T) {
		kind, _, _, _, _, _ := classifyPort53Frame(mkIPv6(6, 53, 40000))
		if kind != dnsFrameIPv6TCP {
			t.Fatalf("got kind=%s", kind)
		}
	})
	t.Run("other", func(t *testing.T) {
		frame := make([]byte, 14+20)
		binary.BigEndian.PutUint16(frame[12:14], 0x0800)
		frame[14] = 0x45
		frame[14+9] = 1 // ICMP
		kind, _, _, _, _, _ := classifyPort53Frame(frame)
		if kind != dnsFrameOther {
			t.Fatalf("got kind=%s", kind)
		}
	})
}
