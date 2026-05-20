//go:build linux

package main

import (
	"testing"
	"time"
)

func TestDNSAnswersFromRow(t *testing.T) {
	var a1, a2, srv [16]byte
	copy(a1[:4], []byte{142, 250, 185, 174})
	copy(a2[:4], []byte{142, 250, 185, 206})
	copy(srv[:4], []byte{8, 8, 8, 8})

	row := DNSRow{
		Ts:             time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
		ClientIP:       a1,
		ServerIP:       srv,
		IsResponse:     1,
		RCode:          0,
		QueryName:      "youtube.com",
		QType:          "A",
		AnswersA:       [][16]byte{a1, a2},
		AnswersATTLs:   []uint32{120, 300},
		Transport:      "udp",
	}

	got := dnsAnswersFromRow(row)
	if len(got) != 2 {
		t.Fatalf("len=%d want 2", len(got))
	}
	if got[0].AnswerType != "A" || got[0].TTL != 120 || got[0].QueryName != "youtube.com" {
		t.Fatalf("first answer: %+v", got[0])
	}
	if got[1].TTL != 300 {
		t.Fatalf("second ttl: %d", got[1].TTL)
	}
	if got[0].ServerIP != srv {
		t.Fatalf("server ip not preserved")
	}
}

func TestDNSAnswersFromRowSkipsQueryAndErrors(t *testing.T) {
	if len(dnsAnswersFromRow(DNSRow{IsResponse: 0})) != 0 {
		t.Fatal("query should produce no answers")
	}
	if len(dnsAnswersFromRow(DNSRow{IsResponse: 1, RCode: 3})) != 0 {
		t.Fatal("NXDOMAIN should produce no answers")
	}
}
