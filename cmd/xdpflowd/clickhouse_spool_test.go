package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
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

// TestResyncToNextMagic verifies the drainer can scan past corrupt bytes and
// land exactly on the next valid frame header. Regression test for the
// "bad frame header" outage where a single torn write blocked the entire
// spool until the consumer.json checkpoint was edited by hand.
func TestResyncToNextMagic(t *testing.T) {
	dir := t.TempDir()
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatal(err)
	}
	row := FlowRow{Bytes: 1, Packets: 1, Etype: 0x0800, Proto: 6}
	payload, err := encodeFramePayload([]FlowRow{row})
	if err != nil {
		t.Fatal(err)
	}
	frame1 := buildFrame(1, payload)
	frame2 := buildFrame(2, payload)
	garbage := bytes.Repeat([]byte{0xAB, 0xCD}, 64) // 128 bytes, no PFLX magic

	var seg bytes.Buffer
	seg.Write(frame1)
	corruptStart := int64(seg.Len())
	seg.Write(garbage)
	expectedResyncOff := int64(seg.Len())
	seg.Write(frame2)

	segPath := filepath.Join(segDir, fmt.Sprintf("%016d.seg", uint64(1)))
	if err := os.WriteFile(segPath, seg.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	// Simulate drainer that just hit the bad bytes mid-segment.
	cp := consumerCheckpoint{Segment: 1, Offset: corruptStart}
	tipSeg := uint64(1)
	tipOff := int64(seg.Len())

	next, scanned, found, err := resyncToNextMagic(segDir, cp, tipSeg, tipOff)
	if err != nil {
		t.Fatalf("resync error: %v", err)
	}
	if !found {
		t.Fatalf("expected to find magic in same segment, got next=%v", next)
	}
	if next.Segment != 1 || next.Offset != expectedResyncOff {
		t.Fatalf("resync landed off-target: got=%v want={1, %d}", next, expectedResyncOff)
	}
	if scanned <= 0 {
		t.Fatalf("scanned bytes should be > 0, got %d", scanned)
	}

	// Sanity: after resync, readNextFrame must succeed and return frame 2.
	nextAfter, rows, err := readNextFrame(segDir, next)
	if err != nil {
		t.Fatalf("readNextFrame after resync: %v", err)
	}
	if len(rows) != 1 || rows[0].Bytes != 1 {
		t.Fatalf("decoded wrong frame after resync: %+v", rows)
	}
	if nextAfter.Offset != int64(seg.Len()) {
		t.Fatalf("post-resync read did not consume frame2: got=%d want=%d", nextAfter.Offset, seg.Len())
	}
}

// TestResyncRollsToNextSegment verifies that a fully-corrupt closed segment
// (no valid magic anywhere) triggers a roll to segment+1 instead of stalling.
func TestResyncRollsToNextSegment(t *testing.T) {
	dir := t.TempDir()
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatal(err)
	}
	garbage := bytes.Repeat([]byte{0xFF}, 4096)
	if err := os.WriteFile(filepath.Join(segDir, fmt.Sprintf("%016d.seg", uint64(4))), garbage, 0o644); err != nil {
		t.Fatal(err)
	}

	// Indicate writer has rotated past segment 4 (tipSeg=5).
	cp := consumerCheckpoint{Segment: 4, Offset: 100}
	next, _, found, err := resyncToNextMagic(segDir, cp, 5, 0)
	if err != nil {
		t.Fatalf("resync error: %v", err)
	}
	if found {
		t.Fatalf("did not expect magic in all-garbage segment")
	}
	if next.Segment != 5 || next.Offset != 0 {
		t.Fatalf("resync should roll to next segment, got=%v", next)
	}
}

// TestResyncStallsInWriterTail verifies that when the corrupt bytes are in
// the writer's *current* segment and no later magic exists yet, resync
// returns "stay put" so the drainer waits for more data.
func TestResyncStallsInWriterTail(t *testing.T) {
	dir := t.TempDir()
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatal(err)
	}
	garbage := bytes.Repeat([]byte{0x55}, 1024)
	if err := os.WriteFile(filepath.Join(segDir, fmt.Sprintf("%016d.seg", uint64(7))), garbage, 0o644); err != nil {
		t.Fatal(err)
	}

	cp := consumerCheckpoint{Segment: 7, Offset: 10}
	next, _, found, err := resyncToNextMagic(segDir, cp, 7, int64(len(garbage)))
	if err != nil {
		t.Fatalf("resync error: %v", err)
	}
	if found {
		t.Fatalf("did not expect magic in garbage")
	}
	if next != cp {
		t.Fatalf("expected stay-put when ceiling=tip and no magic, got=%v", next)
	}
}

// TestResyncRespectsTipCeiling verifies resync does not race ahead into
// not-yet-fsynced bytes past the writer tip even if the segment file extends
// further on disk (e.g. mmap pre-allocation in a future writer change).
func TestResyncRespectsTipCeiling(t *testing.T) {
	dir := t.TempDir()
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatal(err)
	}
	row := FlowRow{Bytes: 2, Packets: 2}
	payload, err := encodeFramePayload([]FlowRow{row})
	if err != nil {
		t.Fatal(err)
	}
	good := buildFrame(11, payload)

	var seg bytes.Buffer
	seg.Write(bytes.Repeat([]byte{0x00}, 50))
	tipOff := int64(seg.Len()) // writer published only 50 bytes
	seg.Write(good)            // disk has more, but writer hasn't ack'd it

	segPath := filepath.Join(segDir, fmt.Sprintf("%016d.seg", uint64(2)))
	if err := os.WriteFile(segPath, seg.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	cp := consumerCheckpoint{Segment: 2, Offset: 5}
	next, _, found, err := resyncToNextMagic(segDir, cp, 2, tipOff)
	if err != nil {
		t.Fatalf("resync error: %v", err)
	}
	if found {
		t.Fatalf("must not find magic past writer tip; got next=%v", next)
	}
	if next != cp {
		t.Fatalf("expected stay-put, got=%v", next)
	}

	// And once writer tip advances, resync must find the magic.
	expected := int64(50)
	next2, _, found2, err := resyncToNextMagic(segDir, cp, 2, int64(seg.Len()))
	if err != nil {
		t.Fatalf("resync error after tip advance: %v", err)
	}
	if !found2 || next2.Offset != expected {
		t.Fatalf("expected magic at off=%d, got found=%v next=%v", expected, found2, next2)
	}
	// Sanity check: the magic at expected offset is indeed PFLX.
	got := binary.BigEndian.Uint32(seg.Bytes()[expected : expected+4])
	if got != spoolFrameMagicBE {
		t.Fatalf("test setup wrong: got magic %#x want %#x", got, spoolFrameMagicBE)
	}
}
