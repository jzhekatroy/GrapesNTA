package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func writeSegFile(t *testing.T, segDir string, id uint64) {
	t.Helper()
	path := filepath.Join(segDir, fmt.Sprintf("%016d.seg", id))
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
}

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

// TestLoadCheckpointCorruptJSONRecovers verifies that a partially-written or
// hand-edited consumer.json does not crash-loop the pipeline. The bad file
// must be quarantined and the loader must return a safe default. Regression
// for the 2026-05-19 outage where `{"segment":,"offset":0}` left xdpflowd
// restarting every few seconds and never resuming inserts.
func TestLoadCheckpointCorruptJSONRecovers(t *testing.T) {
	dir := t.TempDir()
	metaDir := filepath.Join(dir, "meta")
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metaDir, "consumer.json"), []byte(`{"segment":,"offset":0}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cp, err := loadCheckpoint(quietTestLogger(), dir)
	if err != nil {
		t.Fatalf("loadCheckpoint must not return error for corrupt JSON, got %v", err)
	}
	if cp != (consumerCheckpoint{Segment: 1, Offset: 0}) {
		t.Fatalf("expected default checkpoint, got %v", cp)
	}

	// Original must have been quarantined.
	ents, err := os.ReadDir(metaDir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "consumer.json.corrupt.") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected quarantine file consumer.json.corrupt.* in %s, entries=%v", metaDir, ents)
	}
}

// TestLoadCheckpointMissingReturnsDefault confirms first-start behavior is
// unchanged: no file → fresh-start checkpoint, no error.
func TestLoadCheckpointMissingReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	cp, err := loadCheckpoint(quietTestLogger(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cp != (consumerCheckpoint{Segment: 1, Offset: 0}) {
		t.Fatalf("expected default checkpoint, got %v", cp)
	}
}

// TestNormalizeCheckpointAheadOfWriter covers the spool-cleanup regression:
// consumer.json points to a segment far beyond what the writer ever wrote,
// usually because the spool dir was wiped while keeping meta/. Without
// normalization the drainer waits forever AND cleanupAckedSegments would
// delete every real segment on the first ack.
func TestNormalizeCheckpointAheadOfWriter(t *testing.T) {
	dir := t.TempDir()
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeSegFile(t, segDir, 3)
	writeSegFile(t, segDir, 4)
	writeSegFile(t, segDir, 5)

	cp := consumerCheckpoint{Segment: 4000, Offset: 43929469}
	fixed, changed := normalizeCheckpoint(quietTestLogger(), segDir, cp)
	if !changed {
		t.Fatalf("expected correction, got changed=false")
	}
	if fixed != (consumerCheckpoint{Segment: 3, Offset: 0}) {
		t.Fatalf("expected reset to minSeg=3 off=0, got %v", fixed)
	}
}

// TestNormalizeCheckpointBehindRetention covers the retention case: segments
// older than the consumer checkpoint were deleted by an external cleanup,
// the drainer must skip forward instead of looping on os.ErrNotExist.
func TestNormalizeCheckpointBehindRetention(t *testing.T) {
	dir := t.TempDir()
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeSegFile(t, segDir, 100)
	writeSegFile(t, segDir, 101)

	cp := consumerCheckpoint{Segment: 50, Offset: 1234}
	fixed, changed := normalizeCheckpoint(quietTestLogger(), segDir, cp)
	if !changed {
		t.Fatalf("expected correction, got changed=false")
	}
	if fixed != (consumerCheckpoint{Segment: 100, Offset: 0}) {
		t.Fatalf("expected reset to minSeg=100 off=0, got %v", fixed)
	}
}

// TestNormalizeCheckpointWithinRange verifies that legitimate checkpoints —
// including the one pointing at the writer's tip+1 (just rotated) — are
// left untouched.
func TestNormalizeCheckpointWithinRange(t *testing.T) {
	dir := t.TempDir()
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeSegFile(t, segDir, 10)
	writeSegFile(t, segDir, 11)
	writeSegFile(t, segDir, 12)

	cases := []consumerCheckpoint{
		{Segment: 10, Offset: 0},
		{Segment: 11, Offset: 4096},
		{Segment: 12, Offset: 999_999},
		{Segment: 13, Offset: 0}, // tip+1 (writer just rotated)
	}
	for _, cp := range cases {
		fixed, changed := normalizeCheckpoint(quietTestLogger(), segDir, cp)
		if changed {
			t.Fatalf("expected no correction for %v, got fixed=%v changed=true", cp, fixed)
		}
		if fixed != cp {
			t.Fatalf("expected fixed=%v, got %v", cp, fixed)
		}
	}
}

// TestNormalizeCheckpointNoSegmentsLeavesAsIs ensures we do not touch the
// checkpoint when the writer hasn't created any segments yet (fresh spool):
// the drainer will simply wait for the first .seg to appear.
func TestNormalizeCheckpointNoSegmentsLeavesAsIs(t *testing.T) {
	dir := t.TempDir()
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cp := consumerCheckpoint{Segment: 1, Offset: 0}
	fixed, changed := normalizeCheckpoint(quietTestLogger(), segDir, cp)
	if changed {
		t.Fatalf("expected no correction with empty segment dir, got changed=true fixed=%v", fixed)
	}
	if fixed != cp {
		t.Fatalf("expected unchanged, got %v", fixed)
	}
}

// TestLoadAndNormalizeCheckpointPersists verifies that when normalization
// rewrites the checkpoint, the corrected value is also persisted to disk so
// any subsequent reader (drainer, after-restart pipeline) sees it.
func TestLoadAndNormalizeCheckpointPersists(t *testing.T) {
	dir := t.TempDir()
	metaDir := filepath.Join(dir, "meta")
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeSegFile(t, segDir, 7)
	writeSegFile(t, segDir, 8)

	if err := os.WriteFile(filepath.Join(metaDir, "consumer.json"),
		[]byte(`{"segment":4000,"offset":43929469}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cp, err := loadAndNormalizeCheckpoint(quietTestLogger(), dir)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cp != (consumerCheckpoint{Segment: 7, Offset: 0}) {
		t.Fatalf("expected normalized cp, got %v", cp)
	}

	// Re-load: must be the corrected value, not the original ahead-of-writer one.
	cp2, err := loadCheckpoint(quietTestLogger(), dir)
	if err != nil {
		t.Fatalf("re-load failed: %v", err)
	}
	if cp2 != cp {
		t.Fatalf("expected persisted normalized cp=%v, got %v", cp, cp2)
	}
}
