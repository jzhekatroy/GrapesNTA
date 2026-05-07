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
