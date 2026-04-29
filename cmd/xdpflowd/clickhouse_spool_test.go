package main

import (
	"hash/crc32"
	"testing"
	"time"
)

func TestEncodeDecodeFlowRows(t *testing.T) {
	now := time.Date(2026, 4, 28, 12, 0, 0, 123456789, time.UTC)
	var samp, src, dst [16]byte
	copy(src[:4], []byte{10, 0, 0, 1})
	copy(dst[:4], []byte{10, 0, 0, 2})
	rows := []FlowRow{
		{
			Date:             now,
			TimeInsertedNs:   now,
			TimeReceivedNs:   now,
			TimeFlowStartNs:  now,
			SequenceNum:      0,
			SamplingRate:     1,
			SamplerAddress:   samp,
			SrcAddr:          src,
			DstAddr:          dst,
			SrcAS:            0,
			DstAS:            0,
			Etype:            0x0800,
			Proto:            6,
			SrcPort:          443,
			DstPort:          54321,
			Bytes:            1000,
			Packets:          10,
		},
	}
	b, err := encodeFramePayload(rows)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeFramePayload(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Bytes != rows[0].Bytes || got[0].Proto != rows[0].Proto {
		t.Fatalf("decode mismatch: %+v", got)
	}
	frame := buildFrame(7, b)
	seq, pl, crc, ok := parseFrameHeader(frame[:spoolFrameHeaderLen])
	if !ok || seq != 7 || int(pl) != len(b) {
		t.Fatalf("header mismatch seq=%d pl=%d ok=%v", seq, pl, ok)
	}
	payload := frame[spoolFrameHeaderLen:]
	if crc32.ChecksumIEEE(payload) != crc {
		t.Fatalf("crc mismatch")
	}
	out2, err := decodeFramePayload(payload)
	if err != nil || len(out2) != 1 {
		t.Fatalf("frame payload decode: %v len=%d", err, len(out2))
	}
}
