package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// sFlow v5 sample-type formats (enterprise 0).
const (
	sampleFlow        = 1
	sampleCounter     = 2
	sampleFlowExp     = 3
	sampleCounterExp  = 4
)

// Flow record formats (enterprise 0).
const (
	frRawHeader       = 1    // raw packet header
	frSampledEthernet = 2    // sampled ethernet frame data
	frSampledIPv4     = 3    // sampled IPv4 header data
	frSampledIPv6     = 4    // sampled IPv6 header data
	frExtSwitch       = 1001 // extended switch (VLAN/priority)
	frExtRouter       = 1002 // extended router (nexthop + masks)
	frExtGateway      = 1003 // extended gateway (AS path, communities)
	frExtUser         = 1004
	frExtURL          = 1005
	frExtMPLS         = 1006
	frExtNAT          = 1007
)

// Counter record formats (enterprise 0).
const (
	crGenericIf   = 1    // generic interface counters
	crEthernet    = 2    // ethernet interface counters
	crTokenRing   = 3
	crVG          = 4
	crVLAN        = 5
	crProcessor   = 1001 // cpu/memory
	crHostDescr   = 2000
	crHostAdapters= 2001
	crHostParent  = 2002
	crHostCPU     = 2003
	crHostMemory  = 2004
	crHostDiskIO  = 2005
	crHostNetIO   = 2006
)

const (
	ethTypeVLAN = 0x8100
	ethTypeQinQ = 0x88A8
	ethTypeIPv4 = 0x0800
	ethTypeIPv6 = 0x86DD
	ethTypeARP  = 0x0806
)

// cursor is a minimal, bounds-checked big-endian reader over a byte slice.
// Every getter that would read past the end sets err and returns zero so the
// decoder degrades gracefully on truncated / malformed data instead of panicking.
type cursor struct {
	b   []byte
	pos int
	err error
}

func (c *cursor) remaining() int { return len(c.b) - c.pos }

func (c *cursor) u32() uint32 {
	if c.err != nil || c.pos+4 > len(c.b) {
		c.err = io.ErrUnexpectedEOF
		return 0
	}
	v := binary.BigEndian.Uint32(c.b[c.pos : c.pos+4])
	c.pos += 4
	return v
}

func (c *cursor) u64() uint64 {
	if c.err != nil || c.pos+8 > len(c.b) {
		c.err = io.ErrUnexpectedEOF
		return 0
	}
	v := binary.BigEndian.Uint64(c.b[c.pos : c.pos+8])
	c.pos += 8
	return v
}

func (c *cursor) bytes(n int) []byte {
	if c.err != nil || n < 0 || c.pos+n > len(c.b) {
		c.err = io.ErrUnexpectedEOF
		return nil
	}
	v := c.b[c.pos : c.pos+n]
	c.pos += n
	return v
}

// skip advances the cursor without returning data.
func (c *cursor) skip(n int) {
	if c.err != nil || n < 0 || c.pos+n > len(c.b) {
		c.err = io.ErrUnexpectedEOF
		return
	}
	c.pos += n
}

// Summary accumulates what was seen across the whole capture so we can print a
// compact "what is actually in this stream" report at the end.
type Summary struct {
	Datagrams    uint64
	BadDatagrams uint64

	Agents       map[string]uint64
	SampleTypes  map[uint32]uint64 // flow/counter/expanded
	FlowRecords  map[uint32]uint64 // flow record format -> count
	CounterRecs  map[uint32]uint64 // counter record format -> count
	SamplingRate map[uint32]uint64
	HeaderProto  map[uint32]uint64
	EtherTypes   map[uint32]uint64
	L3Protos     map[uint32]uint64
	VLANs        map[uint16]uint64
	TopSrcPorts  map[uint16]uint64
	TopDstPorts  map[uint16]uint64

	Truncated    uint64 // header_length < frame_length (only a slice of the packet)
	FrameLenMin  uint32
	FrameLenMax  uint32
	HeaderLenMin uint32
	HeaderLenMax uint32
}

func newSummary() *Summary {
	return &Summary{
		Agents:       map[string]uint64{},
		SampleTypes:  map[uint32]uint64{},
		FlowRecords:  map[uint32]uint64{},
		CounterRecs:  map[uint32]uint64{},
		SamplingRate: map[uint32]uint64{},
		HeaderProto:  map[uint32]uint64{},
		EtherTypes:   map[uint32]uint64{},
		L3Protos:     map[uint32]uint64{},
		VLANs:        map[uint16]uint64{},
		TopSrcPorts:  map[uint16]uint64{},
		TopDstPorts:  map[uint16]uint64{},
		FrameLenMin:  ^uint32(0),
		HeaderLenMin: ^uint32(0),
	}
}

// Decoder decodes sFlow v5 datagrams, printing a detailed breakdown for the
// first printBudget datagrams and always feeding the running Summary.
type Decoder struct {
	w           io.Writer
	sum         *Summary
	printBudget int  // remaining datagrams to print in full (tree mode)
	flat        bool // one compact line per sampled packet instead of the tree

	// per-datagram / per-sample context, used for the flat line.
	curExporter string // UDP src ip:port of the sFlow packet (the switch/relay)
	curAgent    string // sFlow agent address (the switch)
	curRate     uint32
	curInIf     uint32
	curOutIf    uint32
	curExtVLAN  uint16 // VLAN from the ext-switch record (fallback if 802.1Q absent)
}

func NewDecoder(w io.Writer, sum *Summary, printBudget int, flat bool) *Decoder {
	return &Decoder{w: w, sum: sum, printBudget: printBudget, flat: flat}
}

func (d *Decoder) printing() bool { return d.printBudget > 0 }

func (d *Decoder) pf(indent int, format string, args ...any) {
	if d.flat || !d.printing() {
		return
	}
	for i := 0; i < indent; i++ {
		fmt.Fprint(d.w, "  ")
	}
	fmt.Fprintf(d.w, format+"\n", args...)
}

// Datagram decodes one sFlow datagram. src is the UDP source (may be empty for
// pcap mode). receivedAt is used only for the header line.
func (d *Decoder) Datagram(b []byte, src string, receivedAt time.Time) {
	d.sum.Datagrams++
	c := &cursor{b: b}

	version := c.u32()
	if version != 5 {
		d.sum.BadDatagrams++
		d.pf(0, "datagram from %s: NOT sFlow v5 (version=%d, %d bytes) — skipped", src, version, len(b))
		d.printBudget--
		return
	}
	agentType := c.u32()
	var agent net.IP
	switch agentType {
	case 1:
		agent = net.IP(c.bytes(4))
	case 2:
		agent = net.IP(c.bytes(16))
	default:
		d.sum.BadDatagrams++
		d.pf(0, "datagram from %s: bad agent addr type %d", src, agentType)
		d.printBudget--
		return
	}
	subAgent := c.u32()
	seq := c.u32()
	uptime := c.u32()
	numSamples := c.u32()

	agentStr := agent.String()
	d.sum.Agents[agentStr]++
	d.curExporter = src
	d.curAgent = agentStr

	d.pf(0, "── datagram from %s  agent=%s sub_agent=%d seq=%d uptime=%s samples=%d bytes=%d",
		src, agentStr, subAgent, seq, uptimeStr(uptime), numSamples, len(b))

	for i := uint32(0); i < numSamples && c.err == nil; i++ {
		sampleType := c.u32()
		sampleLen := int(c.u32())
		if c.err != nil || sampleLen < 0 || sampleLen > c.remaining() {
			d.pf(1, "sample %d: truncated (len=%d, remaining=%d)", i, sampleLen, c.remaining())
			d.sum.BadDatagrams++
			break
		}
		body := c.bytes(sampleLen)
		format := sampleType & 0xFFF
		enterprise := sampleType >> 12
		d.sum.SampleTypes[format]++

		if enterprise != 0 {
			d.pf(1, "sample %d: enterprise=%d format=%d (%d bytes) — non-standard, skipped", i, enterprise, format, sampleLen)
			continue
		}
		switch format {
		case sampleFlow:
			d.flowSample(i, body, false)
		case sampleFlowExp:
			d.flowSample(i, body, true)
		case sampleCounter:
			d.counterSample(i, body, false)
		case sampleCounterExp:
			d.counterSample(i, body, true)
		default:
			d.pf(1, "sample %d: unknown format=%d (%d bytes)", i, format, sampleLen)
		}
	}
	d.printBudget--
}

func (d *Decoder) flowSample(idx uint32, b []byte, expanded bool) {
	c := &cursor{b: b}
	seq := c.u32()
	var samplingRate, samplePool, drops, inIf, outIf, numRecords uint32
	if expanded {
		c.skip(8) // source_id_type + source_id_index
		samplingRate = c.u32()
		samplePool = c.u32()
		drops = c.u32()
		c.skip(4)       // input interface format
		inIf = c.u32()  // input interface value (SNMP ifIndex of ingress port)
		c.skip(4)       // output interface format
		outIf = c.u32() // output interface value (SNMP ifIndex of egress port)
		numRecords = c.u32()
	} else {
		c.skip(4) // source_id
		samplingRate = c.u32()
		samplePool = c.u32()
		drops = c.u32()
		inIf = c.u32()
		outIf = c.u32()
		numRecords = c.u32()
	}
	if c.err != nil {
		d.pf(1, "sample %d: flow%s truncated", idx, expTag(expanded))
		return
	}
	d.sum.SamplingRate[samplingRate]++
	d.curRate = uint32(samplingRate)
	d.curInIf = inIf
	d.curOutIf = outIf
	d.curExtVLAN = 0
	d.pf(1, "sample %d: FLOW%s seq=%d rate=1/%d pool=%d drops=%d in_if=%d out_if=%d records=%d",
		idx, expTag(expanded), seq, samplingRate, samplePool, drops, inIf, outIf, numRecords)

	for r := uint32(0); r < numRecords && c.err == nil; r++ {
		recType := c.u32()
		recLen := int(c.u32())
		if c.err != nil || recLen < 0 || recLen > c.remaining() {
			d.pf(2, "record %d: truncated (len=%d, remaining=%d)", r, recLen, c.remaining())
			break
		}
		rec := c.bytes(recLen)
		format := recType & 0xFFF
		enterprise := recType >> 12
		if enterprise != 0 {
			d.pf(2, "record %d: enterprise=%d format=%d (%d bytes) — skipped", r, enterprise, format, recLen)
			continue
		}
		d.sum.FlowRecords[format]++
		switch format {
		case frRawHeader:
			d.rawHeaderRecord(r, rec)
		case frSampledEthernet:
			d.pf(2, "record %d: sampled-ethernet (%d bytes)", r, recLen)
		case frSampledIPv4:
			d.pf(2, "record %d: sampled-IPv4 (%d bytes)", r, recLen)
		case frSampledIPv6:
			d.pf(2, "record %d: sampled-IPv6 (%d bytes)", r, recLen)
		case frExtSwitch:
			d.extSwitchRecord(r, rec)
		case frExtRouter:
			d.extRouterRecord(r, rec)
		case frExtGateway:
			d.extGatewayRecord(r, rec)
		default:
			d.pf(2, "record %d: flow format=%d (%d bytes) — not decoded", r, format, recLen)
		}
	}
}

func (d *Decoder) rawHeaderRecord(idx uint32, b []byte) {
	c := &cursor{b: b}
	headerProto := c.u32()
	frameLen := c.u32()
	stripped := c.u32()
	headerLen := c.u32()
	if c.err != nil {
		d.pf(2, "record %d: raw-header truncated", idx)
		return
	}
	d.sum.HeaderProto[headerProto]++
	d.updFrameLen(frameLen)
	d.updHeaderLen(headerLen)
	if headerLen < frameLen {
		d.sum.Truncated++
	}
	header := c.bytes(int(headerLen))
	d.pf(2, "record %d: RAW-HEADER proto=%s frame_len=%d stripped=%d header_len=%d%s",
		idx, headerProtoName(headerProto), frameLen, stripped, headerLen, truncNote(headerLen, frameLen))
	if headerProto != 1 || header == nil { // only ETHERNET-ISO88023 decoded
		return
	}
	p := parsePacket(header)
	d.updateSummaryPkt(p)
	if d.flat {
		d.flatLine(frameLen, p)
	} else {
		d.treePrintPkt(p)
	}
}

// packetInfo holds the L2/L3/L4 fields parsed from a (possibly truncated)
// sampled ethernet header. Missing fields stay zero-valued.
type packetInfo struct {
	haveL2    bool
	srcMAC    [6]byte
	dstMAC    [6]byte
	etype     uint32
	vlan      uint16
	ipVer     uint8
	srcIP     net.IP
	dstIP     net.IP
	proto     uint32
	ttl       uint8
	tos       uint8
	totalLen  uint16
	fragOff   uint16
	moreFrag  bool
	dontFrag  bool
	haveL4    bool
	srcPort   uint16
	dstPort   uint16
	tcpFlags  byte
	haveFlags bool
	l4Note    string
}

func (p *packetInfo) isARP() bool { return p.etype == ethTypeARP }

// parsePacket best-effort decodes L2→L4 from a sampled ethernet header.
func parsePacket(b []byte) packetInfo {
	var p packetInfo
	c := &cursor{b: b}
	dm := c.bytes(6)
	sm := c.bytes(6)
	et := uint32(be16(c.bytes(2)))
	if c.err != nil {
		return p
	}
	copy(p.dstMAC[:], dm)
	copy(p.srcMAC[:], sm)
	p.haveL2 = true
	for et == ethTypeVLAN || et == ethTypeQinQ {
		tci := be16(c.bytes(2))
		if p.vlan == 0 {
			p.vlan = tci & 0x0FFF
		}
		et = uint32(be16(c.bytes(2)))
	}
	if c.err != nil {
		return p
	}
	p.etype = et
	switch et {
	case ethTypeIPv4:
		parseIPv4Into(&p, c.b[c.pos:])
	case ethTypeIPv6:
		parseIPv6Into(&p, c.b[c.pos:])
	}
	return p
}

func parseIPv4Into(p *packetInfo, b []byte) {
	if len(b) < 20 {
		return
	}
	ihl := int(b[0]&0x0F) * 4
	p.ipVer = 4
	p.tos = b[1]
	p.totalLen = be16(b[2:4])
	ff := be16(b[6:8])
	p.dontFrag = ff&0x4000 != 0
	p.moreFrag = ff&0x2000 != 0
	p.fragOff = ff & 0x1FFF
	p.ttl = b[8]
	p.proto = uint32(b[9])
	p.srcIP = net.IP(b[12:16])
	p.dstIP = net.IP(b[16:20])
	if ihl < 20 || len(b) < ihl {
		return
	}
	parseL4Into(p, b[ihl:])
}

func parseIPv6Into(p *packetInfo, b []byte) {
	if len(b) < 40 {
		return
	}
	p.ipVer = 6
	p.tos = uint8((be16(b[0:2]) >> 4) & 0xFF)
	p.totalLen = be16(b[4:6])
	next := b[6]
	p.ttl = b[7] // hop limit
	p.srcIP = net.IP(b[8:24])
	p.dstIP = net.IP(b[24:40])
	off := 40
	for {
		switch next {
		case 6, 17, 58: // TCP, UDP, ICMPv6
			p.proto = uint32(next)
			parseL4Into(p, b[off:])
			return
		case 0, 43, 44, 60: // extension headers
			if len(b) < off+2 {
				p.proto = uint32(next)
				return
			}
			nn := b[off]
			hl := int(b[off+1])*8 + 8
			if hl < 8 || len(b) < off+hl {
				p.proto = uint32(next)
				return
			}
			next = nn
			off += hl
		default:
			p.proto = uint32(next)
			return
		}
	}
}

func parseL4Into(p *packetInfo, b []byte) {
	switch p.proto {
	case 6: // TCP
		if len(b) < 4 {
			return
		}
		p.srcPort = be16(b[0:2])
		p.dstPort = be16(b[2:4])
		p.haveL4 = true
		if len(b) >= 14 {
			p.tcpFlags = b[13]
			p.haveFlags = true
		}
	case 17: // UDP
		if len(b) < 4 {
			return
		}
		p.srcPort = be16(b[0:2])
		p.dstPort = be16(b[2:4])
		p.haveL4 = true
	case 1: // ICMP
		if len(b) >= 2 {
			p.l4Note = fmt.Sprintf("icmp type=%d code=%d", b[0], b[1])
		}
	case 58: // ICMPv6
		if len(b) >= 2 {
			p.l4Note = fmt.Sprintf("icmp6 type=%d code=%d", b[0], b[1])
		}
	}
}

func (d *Decoder) updateSummaryPkt(p packetInfo) {
	if !p.haveL2 {
		return
	}
	d.sum.EtherTypes[p.etype]++
	if p.vlan != 0 {
		d.sum.VLANs[p.vlan]++
	}
	if p.ipVer != 0 {
		d.sum.L3Protos[p.proto]++
	}
	if p.haveL4 {
		d.sum.TopSrcPorts[p.srcPort]++
		d.sum.TopDstPorts[p.dstPort]++
	}
}

func (d *Decoder) treePrintPkt(p packetInfo) {
	if !p.haveL2 {
		d.pf(3, "L2: truncated")
		return
	}
	vlanStr := ""
	if p.vlan != 0 {
		vlanStr = fmt.Sprintf(" vlan=%d", p.vlan)
	}
	d.pf(3, "L2: %s -> %s etype=0x%04x%s", macStr(p.srcMAC[:]), macStr(p.dstMAC[:]), p.etype, vlanStr)
	switch p.etype {
	case ethTypeARP:
		d.pf(3, "L3: ARP")
		return
	case ethTypeIPv4, ethTypeIPv6:
	default:
		d.pf(3, "L3: etype 0x%04x (not IP)", p.etype)
		return
	}
	if p.ipVer == 0 {
		d.pf(3, "L3: IP header truncated")
		return
	}
	fragNote := ""
	if p.moreFrag || p.fragOff != 0 {
		fragNote = fmt.Sprintf(" FRAG(off=%d more=%v df=%v)", p.fragOff, p.moreFrag, p.dontFrag)
	}
	if p.ipVer == 4 {
		d.pf(3, "L3: IPv4 %s -> %s proto=%s ttl=%d tos=0x%02x total_len=%d%s",
			p.srcIP, p.dstIP, protoName(p.proto), p.ttl, p.tos, p.totalLen, fragNote)
	} else {
		d.pf(3, "L3: IPv6 %s -> %s next=%s hop_limit=%d tclass=0x%02x%s",
			p.srcIP, p.dstIP, protoName(p.proto), p.ttl, p.tos, fragNote)
	}
	switch {
	case p.haveFlags:
		d.pf(4, "L4: TCP %d -> %d flags=%s", p.srcPort, p.dstPort, tcpFlags(p.tcpFlags))
	case p.haveL4:
		d.pf(4, "L4: %s %d -> %d", protoName(p.proto), p.srcPort, p.dstPort)
	case p.l4Note != "":
		d.pf(4, "L4: %s", p.l4Note)
	}
}

// flatLine prints one line per sampled packet: switch (agent) address, exporter
// UDP endpoint, in/out interface, VLAN, sampling rate, frame size, inner
// IP:port endpoints and MACs — the "packet contents" view.
func (d *Decoder) flatLine(frameLen uint32, p packetInfo) {
	vlan := p.vlan
	if vlan == 0 {
		vlan = d.curExtVLAN
	}
	base := fmt.Sprintf("sw=%-14s exp=%-21s in=%d out=%d vlan=%d rate=1/%d frame=%dB",
		d.curAgent, d.curExporter, d.curInIf, d.curOutIf, vlan, d.curRate, frameLen)
	macs := fmt.Sprintf("mac %s -> %s", macStr(p.srcMAC[:]), macStr(p.dstMAC[:]))
	switch {
	case !p.haveL2:
		fmt.Fprintf(d.w, "%s  <l2 truncated>\n", base)
	case p.isARP():
		fmt.Fprintf(d.w, "%s  ARP  %s\n", base, macs)
	case p.ipVer == 0:
		fmt.Fprintf(d.w, "%s  etype=0x%04x  %s\n", base, p.etype, macs)
	default:
		src := p.srcIP.String()
		dst := p.dstIP.String()
		if p.haveL4 {
			src = fmt.Sprintf("%s:%d", p.srcIP, p.srcPort)
			dst = fmt.Sprintf("%s:%d", p.dstIP, p.dstPort)
		}
		flags := ""
		if p.haveFlags {
			flags = " " + tcpFlags(p.tcpFlags)
		}
		note := ""
		if p.l4Note != "" {
			note = " " + p.l4Note
		}
		fmt.Fprintf(d.w, "%s  %-6s %s -> %s%s%s  ttl=%d  %s\n",
			base, protoName(p.proto), src, dst, flags, note, p.ttl, macs)
	}
}

func (d *Decoder) extSwitchRecord(idx uint32, b []byte) {
	c := &cursor{b: b}
	srcVlan := c.u32()
	srcPri := c.u32()
	dstVlan := c.u32()
	dstPri := c.u32()
	if c.err != nil {
		d.pf(2, "record %d: ext-switch truncated", idx)
		return
	}
	if uint16(srcVlan) != 0 {
		d.sum.VLANs[uint16(srcVlan)]++
	}
	d.curExtVLAN = uint16(srcVlan)
	d.pf(2, "record %d: EXT-SWITCH src_vlan=%d src_pri=%d dst_vlan=%d dst_pri=%d",
		idx, srcVlan, srcPri, dstVlan, dstPri)
}

func (d *Decoder) extRouterRecord(idx uint32, b []byte) {
	c := &cursor{b: b}
	addrType := c.u32()
	var nh net.IP
	switch addrType {
	case 1:
		nh = net.IP(c.bytes(4))
	case 2:
		nh = net.IP(c.bytes(16))
	}
	srcMask := c.u32()
	dstMask := c.u32()
	if c.err != nil {
		d.pf(2, "record %d: ext-router truncated", idx)
		return
	}
	d.pf(2, "record %d: EXT-ROUTER nexthop=%s src_mask=/%d dst_mask=/%d", idx, nh, srcMask, dstMask)
}

func (d *Decoder) extGatewayRecord(idx uint32, b []byte) {
	c := &cursor{b: b}
	addrType := c.u32()
	switch addrType {
	case 1:
		c.skip(4)
	case 2:
		c.skip(16)
	}
	asNum := c.u32()
	srcAS := c.u32()
	srcPeerAS := c.u32()
	pathSegs := c.u32()
	if c.err != nil {
		d.pf(2, "record %d: ext-gateway truncated", idx)
		return
	}
	// Read AS path (dst side) — segments of (seg_type, seg_len, AS[]).
	path := make([]uint32, 0, 16)
	for s := uint32(0); s < pathSegs && c.err == nil && len(path) < 64; s++ {
		c.skip(4) // seg_type
		n := int(c.u32())
		for i := 0; i < n && c.err == nil && len(path) < 64; i++ {
			path = append(path, c.u32())
		}
	}
	d.pf(2, "record %d: EXT-GATEWAY as=%d src_as=%d src_peer_as=%d dst_as_path=%v",
		idx, asNum, srcAS, srcPeerAS, path)
}

func (d *Decoder) counterSample(idx uint32, b []byte, expanded bool) {
	c := &cursor{b: b}
	seq := c.u32()
	if expanded {
		c.skip(8) // source_id_type + index
	} else {
		c.skip(4) // source_id
	}
	numRecords := c.u32()
	if c.err != nil {
		d.pf(1, "sample %d: counter%s truncated", idx, expTag(expanded))
		return
	}
	d.pf(1, "sample %d: COUNTER%s seq=%d records=%d", idx, expTag(expanded), seq, numRecords)
	for r := uint32(0); r < numRecords && c.err == nil; r++ {
		recType := c.u32()
		recLen := int(c.u32())
		if c.err != nil || recLen < 0 || recLen > c.remaining() {
			d.pf(2, "record %d: counter truncated (len=%d, remaining=%d)", r, recLen, c.remaining())
			break
		}
		rec := c.bytes(recLen)
		format := recType & 0xFFF
		enterprise := recType >> 12
		if enterprise != 0 {
			d.pf(2, "record %d: enterprise=%d format=%d (%d bytes) — skipped", r, enterprise, format, recLen)
			continue
		}
		d.sum.CounterRecs[format]++
		switch format {
		case crGenericIf:
			d.genericIfCounters(r, rec)
		case crEthernet:
			d.pf(2, "record %d: ethernet-counters (%d bytes)", r, recLen)
		case crProcessor:
			d.pf(2, "record %d: processor-counters (cpu/mem, %d bytes)", r, recLen)
		default:
			d.pf(2, "record %d: counter format=%d (%d bytes) — %s", r, format, recLen, counterName(format))
		}
	}
}

func (d *Decoder) genericIfCounters(idx uint32, b []byte) {
	c := &cursor{b: b}
	ifIndex := c.u32()
	ifType := c.u32()
	ifSpeed := c.u64()
	ifDirection := c.u32()
	ifStatus := c.u32()
	inOct := c.u64()
	inUcast := c.u32()
	c.u32() // in mcast
	c.u32() // in bcast
	inDisc := c.u32()
	inErr := c.u32()
	c.u32() // in unknown proto
	outOct := c.u64()
	outUcast := c.u32()
	c.u32() // out mcast
	c.u32() // out bcast
	outDisc := c.u32()
	outErr := c.u32()
	if c.err != nil {
		d.pf(2, "record %d: generic-if-counters truncated", idx)
		return
	}
	d.pf(2, "record %d: IF-COUNTERS if_index=%d type=%d speed=%s status=0x%x",
		idx, ifIndex, ifType, speedStr(ifSpeed), ifStatus)
	_ = ifDirection
	d.pf(3, "in : octets=%d ucast=%d disc=%d err=%d", inOct, inUcast, inDisc, inErr)
	d.pf(3, "out: octets=%d ucast=%d disc=%d err=%d", outOct, outUcast, outDisc, outErr)
}

func (d *Decoder) updFrameLen(v uint32) {
	if v < d.sum.FrameLenMin {
		d.sum.FrameLenMin = v
	}
	if v > d.sum.FrameLenMax {
		d.sum.FrameLenMax = v
	}
}

func (d *Decoder) updHeaderLen(v uint32) {
	if v < d.sum.HeaderLenMin {
		d.sum.HeaderLenMin = v
	}
	if v > d.sum.HeaderLenMax {
		d.sum.HeaderLenMax = v
	}
}

// ── formatting helpers ────────────────────────────────────────────────────

func be16(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func expTag(expanded bool) string {
	if expanded {
		return "(expanded)"
	}
	return ""
}

func truncNote(headerLen, frameLen uint32) string {
	if headerLen < frameLen {
		return fmt.Sprintf("  [TRUNCATED: only first %d of %d bytes sampled]", headerLen, frameLen)
	}
	return ""
}

func macStr(b []byte) string {
	if len(b) < 6 {
		return "??"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func tcpFlags(f byte) string {
	names := []struct {
		bit  byte
		name string
	}{
		{0x01, "FIN"}, {0x02, "SYN"}, {0x04, "RST"}, {0x08, "PSH"},
		{0x10, "ACK"}, {0x20, "URG"}, {0x40, "ECE"}, {0x80, "CWR"},
	}
	out := ""
	for _, n := range names {
		if f&n.bit != 0 {
			if out != "" {
				out += "|"
			}
			out += n.name
		}
	}
	if out == "" {
		out = "none"
	}
	return fmt.Sprintf("0x%02x(%s)", f, out)
}

func protoName(p uint32) string {
	switch p {
	case 1:
		return "ICMP(1)"
	case 6:
		return "TCP(6)"
	case 17:
		return "UDP(17)"
	case 47:
		return "GRE(47)"
	case 50:
		return "ESP(50)"
	case 58:
		return "ICMPv6(58)"
	case 89:
		return "OSPF(89)"
	case 132:
		return "SCTP(132)"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func headerProtoName(p uint32) string {
	switch p {
	case 1:
		return "ETHERNET(1)"
	case 11:
		return "IPv4(11)"
	case 12:
		return "IPv6(12)"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func counterName(format uint32) string {
	switch format {
	case crVLAN:
		return "vlan-counters"
	case crHostDescr:
		return "host-description"
	case crHostCPU:
		return "host-cpu"
	case crHostMemory:
		return "host-memory"
	case crHostDiskIO:
		return "host-disk-io"
	case crHostNetIO:
		return "host-net-io"
	default:
		return "not decoded"
	}
}

func speedStr(bps uint64) string {
	switch {
	case bps == 0:
		return "0"
	case bps >= 1_000_000_000:
		return fmt.Sprintf("%dG", bps/1_000_000_000)
	case bps >= 1_000_000:
		return fmt.Sprintf("%dM", bps/1_000_000)
	default:
		return fmt.Sprintf("%d", bps)
	}
}

func uptimeStr(ms uint32) string {
	return (time.Duration(ms) * time.Millisecond).Truncate(time.Second).String()
}
