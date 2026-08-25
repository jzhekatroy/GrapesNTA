package main

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"xdpflowd/internal/flowingest"
)

// Cisco IPv4 template from the live dump: 19 fields, 50-byte records.
var ciscoV4Fields = []nfField{
	{nfFIRST_SWITCHED, 4},
	{nfLAST_SWITCHED, 4},
	{nfIN_BYTES, 4},
	{nfIN_PKTS, 4},
	{nfINPUT_SNMP, 4},
	{nfOUTPUT_SNMP, 4},
	{nfIPV4_SRC_ADDR, 4},
	{nfIPV4_DST_ADDR, 4},
	{nfPROTOCOL, 1},
	{nfSRC_TOS, 1},
	{nfL4_SRC_PORT, 2},
	{nfL4_DST_PORT, 2},
	{nfFLOW_SAMPLER_ID, 1},
	{nfIPV4_NEXT_HOP, 4},
	{nfDST_MASK, 1},
	{nfSRC_MASK, 1},
	{nfTCP_FLAGS, 1},
	{nfDST_AS, 2},
	{nfSRC_AS, 2},
}

func putU16(b []byte, v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return append(b, buf[:]...)
}

func putU32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func nfHeader(count uint16, sysUp, unixSecs, seq, domain uint32) []byte {
	b := putU16(nil, nfVersion)
	b = putU16(b, count)
	b = putU32(b, sysUp)
	b = putU32(b, unixSecs)
	b = putU32(b, seq)
	b = putU32(b, domain)
	return b
}

func buildNFTemplateFlowset(tid uint16, fields []nfField) []byte {
	body := putU16(nil, tid)
	body = putU16(body, uint16(len(fields)))
	for _, f := range fields {
		body = putU16(body, f.Type)
		body = putU16(body, f.Length)
	}
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	out := putU16(nil, nfTemplateFlowset)
	out = putU16(out, uint16(4+len(body)))
	return append(out, body...)
}

func nfDataFlowset(tid uint16, records ...[]byte) []byte {
	body := make([]byte, 0, 64)
	for _, r := range records {
		body = append(body, r...)
	}
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	out := putU16(nil, tid)
	out = putU16(out, uint16(4+len(body)))
	return append(out, body...)
}

func ciscoRecord(src, dst string, sport, dport uint16, proto uint8, bytes, pkts, inIf, outIf, first, last uint32) []byte {
	r := make([]byte, 0, 50)
	r = putU32(r, first)
	r = putU32(r, last)
	r = putU32(r, bytes)
	r = putU32(r, pkts)
	r = putU32(r, inIf)
	r = putU32(r, outIf)
	r = append(r, net.ParseIP(src).To4()...)
	r = append(r, net.ParseIP(dst).To4()...)
	r = append(r, proto, 0) // tos
	r = putU16(r, sport)
	r = putU16(r, dport)
	r = append(r, 0) // sampler id
	r = append(r, net.ParseIP("172.16.0.1").To4()...)
	r = append(r, 24, 24, 24) // masks + tcp flags
	r = putU16(r, 65000)
	r = putU16(r, 65001)
	if len(r) != 50 {
		panic(len(r))
	}
	return r
}

func testExporter() net.IP { return net.ParseIP("172.25.3.14") }

func parseNF(t *testing.T, p *nfParser, payload []byte) []flowingest.FlowRow {
	t.Helper()
	return p.parse(udpDatagram{b: payload, receivedAt: time.Unix(1_787_649_533, 0).UTC(), src: testExporter()})
}

func TestNetFlowV9CiscoTemplate(t *testing.T) {
	p := newNFParser(nil, "netflow-default", 1, time.Hour, nil)
	sysUp := uint32(394_900_000)
	unixSecs := uint32(1_787_649_533)
	first := sysUp - 1_500
	pkt := append(nfHeader(2, sysUp, unixSecs, 1, 1536), buildNFTemplateFlowset(257, ciscoV4Fields)...)
	pkt = append(pkt, nfDataFlowset(257, ciscoRecord("10.1.2.3", "10.4.5.6", 443, 51234, 6, 408, 6, 31, 198, first, sysUp))...)

	rows := parseNF(t, p, pkt)
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	r := rows[0]
	if r.SourceID != "netflow-default" {
		t.Fatalf("source_id=%q", r.SourceID)
	}
	if r.Proto != 6 || r.SrcPort != 443 || r.DstPort != 51234 {
		t.Fatalf("l4 proto=%d %d->%d", r.Proto, r.SrcPort, r.DstPort)
	}
	if r.Bytes != 408 || r.Packets != 6 {
		t.Fatalf("volume bytes=%d pkts=%d", r.Bytes, r.Packets)
	}
	if r.InIf != 31 || r.OutIf != 198 {
		t.Fatalf("if in=%d out=%d", r.InIf, r.OutIf)
	}
	if r.SamplingRate != 1 {
		t.Fatalf("rate=%d", r.SamplingRate)
	}
	if r.Etype != 0x0800 {
		t.Fatalf("etype=%#x", r.Etype)
	}
	wantSrc, _ := flowingest.ParseSamplerAddress("10.1.2.3")
	wantDst, _ := flowingest.ParseSamplerAddress("10.4.5.6")
	if r.SrcAddr != wantSrc || r.DstAddr != wantDst {
		t.Fatalf("addrs %x -> %x", r.SrcAddr, r.DstAddr)
	}
	wantSampler, _ := flowingest.ParseSamplerAddress("172.25.3.14")
	if r.SamplerAddress != wantSampler {
		t.Fatalf("sampler %x", r.SamplerAddress)
	}
	// unix 1787649533, delta 1500ms → start = that instant minus 1.5s
	wantStart := time.Unix(int64(unixSecs), 0).UTC().Add(-1500 * time.Millisecond)
	if !r.TimeFlowStartNs.Equal(wantStart) {
		t.Fatalf("start %s want %s", r.TimeFlowStartNs, wantStart)
	}
}

func TestNetFlowV9UnknownTemplateDropped(t *testing.T) {
	p := newNFParser(nil, "netflow-default", 1, time.Hour, nil)
	pkt := append(nfHeader(1, 1, 1, 1, 1536), nfDataFlowset(257, ciscoRecord("10.0.0.1", "10.0.0.2", 1, 2, 17, 76, 1, 1, 2, 1, 1))...)
	rows := parseNF(t, p, pkt)
	if len(rows) != 0 {
		t.Fatalf("expected drop, got %d rows", len(rows))
	}
	if p.metrics.unknownTemplates.Load() != 1 {
		t.Fatalf("unknown_templates=%d", p.metrics.unknownTemplates.Load())
	}
}

func TestNetFlowV9DomainsDoNotShareTemplates(t *testing.T) {
	p := newNFParser(nil, "netflow-default", 1, time.Hour, nil)
	learn := append(nfHeader(1, 1, 1, 1, 1536), buildNFTemplateFlowset(257, ciscoV4Fields)...)
	_ = parseNF(t, p, learn)
	other := append(nfHeader(1, 1, 1, 2, 1280), nfDataFlowset(257, ciscoRecord("10.0.0.1", "10.0.0.2", 1, 2, 17, 76, 1, 1, 2, 1, 1))...)
	if rows := parseNF(t, p, other); len(rows) != 0 {
		t.Fatalf("domain 1280 used domain 1536 template")
	}
}

func TestNetFlowV9UnsupportedVersions(t *testing.T) {
	p := newNFParser(nil, "netflow-default", 1, time.Hour, nil)
	v5 := putU16(nil, 5)
	v5 = append(v5, make([]byte, 22)...)
	if rows := parseNF(t, p, v5); len(rows) != 0 || p.metrics.unsupportedV5.Load() != 1 {
		t.Fatalf("v5: rows=%d unsupported=%d", len(rows), p.metrics.unsupportedV5.Load())
	}
	v10 := putU16(nil, 10)
	v10 = append(v10, make([]byte, 22)...)
	if rows := parseNF(t, p, v10); len(rows) != 0 || p.metrics.unsupportedIPFIX.Load() != 1 {
		t.Fatalf("ipfix: rows=%d unsupported=%d", len(rows), p.metrics.unsupportedIPFIX.Load())
	}
}

func TestNetFlowV9SamplingFromOptionTemplate(t *testing.T) {
	p := newNFParser(nil, "netflow-default", 1, time.Hour, nil)
	// Options template: scope FLOW_SAMPLER_ID (1), option RANDOM_INTERVAL (4)
	optBody := putU16(nil, 260)
	optBody = putU16(optBody, 4) // scope length
	optBody = putU16(optBody, 4) // option length
	optBody = putU16(optBody, nfFLOW_SAMPLER_ID)
	optBody = putU16(optBody, 1)
	optBody = putU16(optBody, nfFLOW_SAMPLER_RANDOM_INTERVAL)
	optBody = putU16(optBody, 4)
	for len(optBody)%4 != 0 {
		optBody = append(optBody, 0)
	}
	optFS := putU16(nil, nfOptionsFlowset)
	optFS = putU16(optFS, uint16(4+len(optBody)))
	optFS = append(optFS, optBody...)

	optRec := []byte{7} // sampler id 7
	optRec = putU32(optRec, 1000)
	for len(optRec)%4 != 0 {
		optRec = append(optRec, 0)
	}
	optData := putU16(nil, 260)
	optData = putU16(optData, uint16(4+len(optRec)))
	optData = append(optData, optRec...)

	learn := append(nfHeader(2, 1, 1, 1, 1536), optFS...)
	learn = append(learn, optData...)
	_ = parseNF(t, p, learn)

	rec := ciscoRecord("10.1.2.3", "10.4.5.6", 80, 9, 6, 100, 2, 1, 2, 1, 1)
	rec[38] = 7 // FLOW_SAMPLER_ID sits after first/last/bytes/pkts/ifaces/addrs/proto/tos/ports
	data := append(nfHeader(1, 1, 1, 2, 1536), buildNFTemplateFlowset(257, ciscoV4Fields)...)
	data = append(data, nfDataFlowset(257, rec)...)
	rows := parseNF(t, p, data)
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	if rows[0].SamplingRate != 1000 {
		t.Fatalf("rate=%d", rows[0].SamplingRate)
	}
	if rows[0].Bytes != 100*1000 || rows[0].Packets != 2*1000 {
		t.Fatalf("scaled bytes=%d pkts=%d", rows[0].Bytes, rows[0].Packets)
	}
	if p.metrics.rateFromOption.Load() != 1 {
		t.Fatalf("rate_from_option=%d", p.metrics.rateFromOption.Load())
	}
}

func TestNetFlowV9ConfigRateWhenNoOption(t *testing.T) {
	p := newNFParser(nil, "netflow-default", 64, time.Hour, nil)
	pkt := append(nfHeader(2, 1, 1, 1, 1536), buildNFTemplateFlowset(257, ciscoV4Fields)...)
	pkt = append(pkt, nfDataFlowset(257, ciscoRecord("10.0.0.1", "10.0.0.2", 1, 2, 17, 80, 1, 1, 2, 1, 1))...)
	rows := parseNF(t, p, pkt)
	if len(rows) != 1 || rows[0].SamplingRate != 64 || rows[0].Bytes != 80*64 {
		t.Fatalf("row=%+v", rows)
	}
}

func TestNetFlowV9LiveDump(t *testing.T) {
	exporter := net.ParseIP("172.25.3.14")
	p := newNFParser(nil, "netflow-default", 1, time.Hour, nil)
	now := time.Date(2026, 8, 25, 9, 18, 53, 0, time.UTC)

	before := readTestdata(t, "nf9_before_template.bin")
	if rows := p.parse(udpDatagram{b: before, receivedAt: now, src: exporter}); len(rows) != 0 {
		t.Fatalf("blind start produced %d rows", len(rows))
	}
	if p.metrics.unknownTemplates.Load() == 0 {
		t.Fatal("expected unknown template on cold start")
	}

	learn := readTestdata(t, "nf9_template257.bin")
	learned := p.parse(udpDatagram{b: learn, receivedAt: now, src: exporter})
	if len(learned) == 0 {
		t.Fatal("template packet also carries data records; expected rows")
	}
	r := learned[0]
	if r.Etype != 0x0800 || r.InIf == 0 || r.SamplingRate != 1 {
		t.Fatalf("first live row etype=%#x in=%d rate=%d proto=%d", r.Etype, r.InIf, r.SamplingRate, r.Proto)
	}

	data := readTestdata(t, "nf9_data257.bin")
	more := p.parse(udpDatagram{b: data, receivedAt: now.Add(time.Second), src: exporter})
	if len(more) == 0 {
		t.Fatal("data packet after template produced no rows")
	}

	// Domain 1280 must not decode until its own template arrives.
	other := readTestdata(t, "nf9_template256.bin")
	// The 256 file is the first packet that contains template 256; before
	// parsing it, a 256-only data packet is not in testdata. Parsing this
	// packet must learn tid 256 and emit rows for domain 1280.
	rows256 := p.parse(udpDatagram{b: other, receivedAt: now.Add(2 * time.Minute), src: exporter})
	if len(rows256) == 0 {
		t.Fatal("template 256 packet should decode its own data records")
	}
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFlowStartTimeWrap(t *testing.T) {
	// sysUp just wrapped past 0; firstSwitched is near uint32 max.
	got := flowStartTime(1_700_000_000, 50, 0xffffff00)
	// delta = 50 - 0xffffff00 = 0x132 (306 ms)
	want := time.Unix(1_700_000_000, 0).UTC().Add(-306 * time.Millisecond)
	if !got.Equal(want) {
		t.Fatalf("got %s want %s", got, want)
	}
}
