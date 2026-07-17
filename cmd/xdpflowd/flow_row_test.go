package main

import (
	"testing"
	"time"
)

func TestFlowRowFromKVMapsTCPFlagsAndIPMeta(t *testing.T) {
	receivedAt := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	m := newFlowRowMapper(ExportClock{
		ExporterStart: receivedAt,
		BpfStartNs:    1_000_000_000,
	}, [16]byte{}, 42, "netflow", nil)

	fv := flowKV{
		k: FlowKey{
			Proto:     6,
			IPVersion: 4,
			SrcPort:   0x901f, // htons(8080)
			DstPort:   0xbb01, // htons(443)
		},
		v: FlowValue{
			Packets:     10,
			Bytes:       640,
			FirstSeenNs: 1_500_000_000,
			TCPFlagsOR:  0x02, // SYN
			Tos:         0x48,
			TTLMin:      52,
			TTLMax:      64,
		},
	}

	row := flowRowFromKV(fv, m, receivedAt)

	if row.TCPFlags != 0x02 {
		t.Fatalf("TCPFlags = %#x, want 0x02", row.TCPFlags)
	}
	if row.IPTos != 0x48 {
		t.Fatalf("IPTos = %#x, want 0x48", row.IPTos)
	}
	if row.IPTTL != 52 {
		t.Fatalf("IPTTL = %d, want 52 (TTLMin)", row.IPTTL)
	}
	if row.SourceID != "netflow" {
		t.Fatalf("SourceID = %q, want netflow", row.SourceID)
	}
	if row.Proto != 6 {
		t.Fatalf("Proto = %d, want 6", row.Proto)
	}
}
