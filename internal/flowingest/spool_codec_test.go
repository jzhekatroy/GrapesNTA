package flowingest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleFullRow() FlowRow {
	t1 := time.Date(2026, 6, 30, 10, 11, 12, 123456789, time.UTC)
	t2 := time.Date(2026, 6, 30, 10, 11, 13, 987654321, time.UTC)
	var samp, src, dst [16]byte
	copy(samp[:4], []byte{192, 168, 1, 1})
	copy(src[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(dst[:4], []byte{10, 0, 0, 2})
	return FlowRow{
		Date:                  t1,
		TimeInsertedNs:        t1,
		TimeReceivedNs:        t2,
		TimeFlowStartNs:       t2,
		SequenceNum:           4294967000,
		SamplingRate:          1024,
		SamplerAddress:        samp,
		SourceID:              "m61-xdp",
		SrcAddr:               src,
		DstAddr:               dst,
		SrcAS:                 64512,
		DstAS:                 15169,
		SrcASN:                64512,
		DstASN:                15169,
		Direction:             "egress",
		SrcKind:               "internal",
		DstKind:               "external",
		SrcLabel:              "srclabel",
		DstLabel:              "dstlabel",
		SrcOperator:           "op-a",
		DstOperator:           "op-b",
		SrcAttachmentKind:     "sa-kind",
		DstAttachmentKind:     "da-kind",
		SrcAttachmentBoundary: "sa-bound",
		DstAttachmentBoundary: "da-bound",
		SrcAttachmentLabel:    "sa-label",
		DstAttachmentLabel:    "da-label",
		SrcAttachmentOperator: "sa-op",
		DstAttachmentOperator: "da-op",
		SrcEndpointScope:      "s-scope",
		DstEndpointScope:      "d-scope",
		SrcEndpointSource:     "s-source",
		DstEndpointSource:     "d-source",
		SrcNetworkName:        "s-net",
		DstNetworkName:        "d-net",
		SrcNetworkRole:        "s-nrole",
		DstNetworkRole:        "d-nrole",
		SrcRole:               "s-role",
		DstRole:               "d-role",
		SrcEntity:             "s-entity",
		DstEntity:             "d-entity",
		SrcVLAN:               100,
		DstVLAN:               200,
		Etype:                 0x86DD,
		Proto:                 17,
		SrcPort:               53,
		DstPort:               65000,
		Bytes:                 9876543210,
		Packets:               123456,
	}
}

func flowRowsEqual(t *testing.T, want, got FlowRow) {
	t.Helper()
	if !want.Date.Equal(got.Date) || !want.TimeInsertedNs.Equal(got.TimeInsertedNs) ||
		!want.TimeReceivedNs.Equal(got.TimeReceivedNs) || !want.TimeFlowStartNs.Equal(got.TimeFlowStartNs) {
		t.Fatalf("time fields mismatch:\n want=%+v\n got =%+v", want, got)
	}
	// Zero out times so the remaining struct compares with ==.
	want.Date, got.Date = time.Time{}, time.Time{}
	want.TimeInsertedNs, got.TimeInsertedNs = time.Time{}, time.Time{}
	want.TimeReceivedNs, got.TimeReceivedNs = time.Time{}, time.Time{}
	want.TimeFlowStartNs, got.TimeFlowStartNs = time.Time{}, time.Time{}
	if want != got {
		t.Fatalf("row mismatch:\n want=%+v\n got =%+v", want, got)
	}
}

func TestBinaryCodecRoundTripAllFields(t *testing.T) {
	rows := []FlowRow{sampleFullRow(), {}, {SourceID: "only-source", Bytes: 1, Packets: 1}}
	payload, err := encodeFlowRowsBinary(rows)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeFlowRowsBinary(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(rows) {
		t.Fatalf("row count: want %d got %d", len(rows), len(got))
	}
	for i := range rows {
		flowRowsEqual(t, rows[i], got[i])
	}
}

func TestBinaryCodecEmpty(t *testing.T) {
	payload, err := encodeFlowRowsBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeFlowRowsBinary(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %d rows", len(got))
	}
}

func TestBinaryCodecTruncated(t *testing.T) {
	payload, err := encodeFlowRowsBinary([]FlowRow{sampleFullRow()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeFlowRowsBinary(payload[:len(payload)-4]); err == nil {
		t.Fatal("expected error on truncated payload")
	}
	if _, err := decodeFlowRowsBinary(append(payload, 0x00)); err == nil {
		t.Fatal("expected error on trailing bytes")
	}
}

// TestSpoolMixedVersionSegment writes a legacy gob frame (v1) and a binary
// frame (v2) into one segment and verifies readNextFrame decodes both. This is
// the rolling-restart path: old on-disk frames must still drain after the
// writer switches to the binary codec.
func TestSpoolMixedVersionSegment(t *testing.T) {
	dir := t.TempDir()
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rowGob := FlowRow{SourceID: "legacy", Bytes: 111, Packets: 11, Proto: 6, DstPort: 443}
	rowBin := sampleFullRow()

	gobPayload, err := encodeFramePayload([]FlowRow{rowGob})
	if err != nil {
		t.Fatal(err)
	}
	binPayload, err := encodeFlowRowsBinary([]FlowRow{rowBin})
	if err != nil {
		t.Fatal(err)
	}
	frameGob := buildFrame(1, spoolFrameVersionGob, gobPayload)
	frameBin := buildFrame(2, spoolFrameVersionBinary, binPayload)

	segPath := filepath.Join(segDir, fmt.Sprintf("%016d.seg", uint64(1)))
	f, err := os.Create(segPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(frameGob, frameBin...)); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	cp := consumerCheckpoint{Segment: 1, Offset: 0}
	next, rows, err := readNextFrame(segDir, cp)
	if err != nil {
		t.Fatalf("read gob frame: %v", err)
	}
	if len(rows) != 1 || rows[0].SourceID != "legacy" || rows[0].Bytes != 111 {
		t.Fatalf("gob frame decode mismatch: %+v", rows)
	}

	_, rows2, err := readNextFrame(segDir, next)
	if err != nil {
		t.Fatalf("read binary frame: %v", err)
	}
	if len(rows2) != 1 {
		t.Fatalf("binary frame row count: %d", len(rows2))
	}
	flowRowsEqual(t, rowBin, rows2[0])
}
