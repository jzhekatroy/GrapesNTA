package flowingest

import (
	"encoding/binary"
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
		SrcMAC:                [6]byte{0x02, 0x42, 0xac, 0x11, 0x00, 0x02},
		DstMAC:                [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
	}
}

// encodeFlowRowsBinaryNoMAC replicates the legacy frame-version-2 wire layout
// (no trailing SrcMAC/DstMAC). Test-only: it lets us assert that version-2
// frames written before the MAC rollout still decode after the codec learned to
// append MAC. Kept in lockstep with encodeFlowRowsBinary minus the MAC writes.
func encodeFlowRowsBinaryNoMAC(rows []FlowRow) []byte {
	var buf []byte
	var vtmp [binary.MaxVarintLen64]byte
	putUvarint := func(x uint64) {
		n := binary.PutUvarint(vtmp[:], x)
		buf = append(buf, vtmp[:n]...)
	}
	putI64 := func(v int64) {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], uint64(v))
		buf = append(buf, b[:]...)
	}
	putTime := func(t time.Time) {
		if t.IsZero() {
			putI64(spoolZeroTimeSentinel)
			return
		}
		putI64(t.UnixNano())
	}
	putStr := func(s string) {
		putUvarint(uint64(len(s)))
		buf = append(buf, s...)
	}
	putUvarint(uint64(len(rows)))
	for i := range rows {
		r := &rows[i]
		putTime(r.Date)
		putTime(r.TimeInsertedNs)
		putTime(r.TimeReceivedNs)
		putTime(r.TimeFlowStartNs)
		putUvarint(uint64(r.SequenceNum))
		putUvarint(r.SamplingRate)
		buf = append(buf, r.SamplerAddress[:]...)
		putStr(r.SourceID)
		buf = append(buf, r.SrcAddr[:]...)
		buf = append(buf, r.DstAddr[:]...)
		putUvarint(uint64(r.SrcAS))
		putUvarint(uint64(r.DstAS))
		putUvarint(uint64(r.SrcASN))
		putUvarint(uint64(r.DstASN))
		for _, s := range []string{
			r.Direction, r.SrcKind, r.DstKind, r.SrcLabel, r.DstLabel,
			r.SrcOperator, r.DstOperator,
			r.SrcAttachmentKind, r.DstAttachmentKind,
			r.SrcAttachmentBoundary, r.DstAttachmentBoundary,
			r.SrcAttachmentLabel, r.DstAttachmentLabel,
			r.SrcAttachmentOperator, r.DstAttachmentOperator,
			r.SrcEndpointScope, r.DstEndpointScope,
			r.SrcEndpointSource, r.DstEndpointSource,
			r.SrcNetworkName, r.DstNetworkName,
			r.SrcNetworkRole, r.DstNetworkRole,
			r.SrcRole, r.DstRole, r.SrcEntity, r.DstEntity,
		} {
			putStr(s)
		}
		putUvarint(uint64(r.SrcVLAN))
		putUvarint(uint64(r.DstVLAN))
		putUvarint(uint64(r.Etype))
		putUvarint(uint64(r.Proto))
		putUvarint(uint64(r.SrcPort))
		putUvarint(uint64(r.DstPort))
		putUvarint(r.Bytes)
		putUvarint(r.Packets)
	}
	return buf
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

// TestBinaryCodecV2FrameDecodesWithoutMAC verifies that a legacy version-2
// payload (no trailing MAC) decodes through the version dispatch with zero MAC
// fields — the rolling-restart guarantee for frames written before MAC support.
func TestBinaryCodecV2FrameDecodesWithoutMAC(t *testing.T) {
	src := sampleFullRow()
	// MAC set on the source row must NOT appear after a v2 decode: v2 frames
	// never carried MAC, so the decoded rows are MAC-zero regardless.
	wantNoMAC := src
	wantNoMAC.SrcMAC = [6]byte{}
	wantNoMAC.DstMAC = [6]byte{}

	payload := encodeFlowRowsBinaryNoMAC([]FlowRow{src})
	got, err := decodeFramePayloadVersioned(spoolFrameVersionBinary, payload)
	if err != nil {
		t.Fatalf("decode v2 payload: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("v2 row count: want 1 got %d", len(got))
	}
	flowRowsEqual(t, wantNoMAC, got[0])
}

// TestSpoolMixedVersionSegment writes a legacy gob frame (v1), a legacy binary
// frame without MAC (v2), and a current binary frame with MAC (v3) into one
// segment and verifies readNextFrame decodes all three. This is the
// rolling-restart path: old on-disk frames must still drain after the writer
// switches to the MAC-bearing codec.
func TestSpoolMixedVersionSegment(t *testing.T) {
	dir := t.TempDir()
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rowGob := FlowRow{SourceID: "legacy", Bytes: 111, Packets: 11, Proto: 6, DstPort: 443}
	rowV2 := FlowRow{SourceID: "binary-v2", Bytes: 222, Packets: 22, Proto: 17, DstPort: 53}
	rowV3 := sampleFullRow()

	gobPayload, err := encodeFramePayload([]FlowRow{rowGob})
	if err != nil {
		t.Fatal(err)
	}
	v2Payload := encodeFlowRowsBinaryNoMAC([]FlowRow{rowV2})
	v3Payload, err := encodeFlowRowsBinary([]FlowRow{rowV3})
	if err != nil {
		t.Fatal(err)
	}
	frameGob := buildFrame(1, spoolFrameVersionGob, gobPayload)
	frameV2 := buildFrame(2, spoolFrameVersionBinary, v2Payload)
	frameV3 := buildFrame(3, spoolFrameVersionBinaryMAC, v3Payload)

	segPath := filepath.Join(segDir, fmt.Sprintf("%016d.seg", uint64(1)))
	f, err := os.Create(segPath)
	if err != nil {
		t.Fatal(err)
	}
	all := append(append(append([]byte{}, frameGob...), frameV2...), frameV3...)
	if _, err := f.Write(all); err != nil {
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

	next2, rowsV2, err := readNextFrame(segDir, next)
	if err != nil {
		t.Fatalf("read v2 binary frame: %v", err)
	}
	if len(rowsV2) != 1 || rowsV2[0].SourceID != "binary-v2" || rowsV2[0].Bytes != 222 {
		t.Fatalf("v2 frame decode mismatch: %+v", rowsV2)
	}
	if rowsV2[0].SrcMAC != ([6]byte{}) || rowsV2[0].DstMAC != ([6]byte{}) {
		t.Fatalf("v2 frame must decode with zero MAC: %+v", rowsV2[0])
	}

	_, rowsV3, err := readNextFrame(segDir, next2)
	if err != nil {
		t.Fatalf("read v3 binary frame: %v", err)
	}
	if len(rowsV3) != 1 {
		t.Fatalf("v3 frame row count: %d", len(rowsV3))
	}
	flowRowsEqual(t, rowV3, rowsV3[0])
}
