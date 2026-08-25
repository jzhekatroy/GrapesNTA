package main

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"xdpflowd/internal/flowingest"
)

type nfMetrics struct {
	datagrams         atomic.Uint64
	recordsParsed     atomic.Uint64
	parseErrors       atomic.Uint64
	unknownTemplates  atomic.Uint64
	unsupportedV5     atomic.Uint64
	unsupportedIPFIX  atomic.Uint64
	unsupportedOther  atomic.Uint64
	templatesLearned  atomic.Uint64
	optionTemplates   atomic.Uint64
	optionRecords     atomic.Uint64
	rateFromOption    atomic.Uint64
	rateFromConfig    atomic.Uint64
	rateMismatch      atomic.Uint64
	timeSkewFallback  atomic.Uint64
	incompleteSkipped atomic.Uint64
	udpQueueDrops     atomic.Uint64
}

type nfParser struct {
	log          *slog.Logger
	sourceID     string
	fallbackRate uint64
	store        *nfTemplateStore
	classifier   *flowingest.TrafficClassifier
	metrics      nfMetrics
	rateWarn     sync.Map
}

func newNFParser(log *slog.Logger, sourceID string, fallbackRate uint64, ttl time.Duration, classifier *flowingest.TrafficClassifier) *nfParser {
	if fallbackRate == 0 {
		fallbackRate = 1
	}
	return &nfParser{
		log:          log,
		sourceID:     sourceID,
		fallbackRate: fallbackRate,
		store:        newNFTemplateStore(ttl),
		classifier:   classifier,
	}
}

func (p *nfParser) parse(d udpDatagram) []flowingest.FlowRow {
	p.metrics.datagrams.Add(1)
	if len(d.b) < 2 {
		p.metrics.parseErrors.Add(1)
		return nil
	}
	ver := binary.BigEndian.Uint16(d.b[0:2])
	switch ver {
	case nfVersion:
		return p.parseV9(d)
	case 5:
		p.metrics.unsupportedV5.Add(1)
		return nil
	case 10:
		p.metrics.unsupportedIPFIX.Add(1)
		return nil
	default:
		p.metrics.unsupportedOther.Add(1)
		return nil
	}
}

func (p *nfParser) parseV9(d udpDatagram) []flowingest.FlowRow {
	b := d.b
	if len(b) < nfHeaderLen {
		p.metrics.parseErrors.Add(1)
		return nil
	}
	sysUp := binary.BigEndian.Uint32(b[4:8])
	unixSecs := binary.BigEndian.Uint32(b[8:12])
	domain := binary.BigEndian.Uint32(b[16:20])
	exporter, ok := agentAddressFromIP(d.src)
	if !ok {
		p.metrics.parseErrors.Add(1)
		return nil
	}

	now := d.receivedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var rows []flowingest.FlowRow
	off := nfHeaderLen
	for off+4 <= len(b) {
		fsid := binary.BigEndian.Uint16(b[off : off+2])
		flen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if flen < 4 || off+flen > len(b) {
			p.metrics.parseErrors.Add(1)
			break
		}
		body := b[off+4 : off+flen]
		switch {
		case fsid == nfTemplateFlowset:
			p.learnTemplates(exporter, domain, body, now)
		case fsid == nfOptionsFlowset:
			p.learnOptionTemplates(exporter, domain, body, now)
		case fsid >= nfMinDataTemplateID:
			key := nfTemplateKey{exporter: exporter, domain: domain, id: fsid}
			if opt, ok := p.store.optionTemplate(key, now); ok {
				p.decodeOptionRecords(exporter, domain, body, opt, now)
				break
			}
			tmpl, ok := p.store.dataTemplate(key, now)
			if !ok {
				p.metrics.unknownTemplates.Add(1)
				break
			}
			decoded := p.decodeDataRecords(body, tmpl, exporter, domain, sysUp, unixSecs, now)
			if len(decoded) > 0 {
				rows = append(rows, decoded...)
			}
		default:
			// Reserved / undocumented flowset: skip by length.
		}
		off += flen
	}
	return rows
}

func (p *nfParser) learnTemplates(exporter [16]byte, domain uint32, body []byte, now time.Time) {
	i := 0
	for i+4 <= len(body) {
		tid := binary.BigEndian.Uint16(body[i : i+2])
		nfields := int(binary.BigEndian.Uint16(body[i+2 : i+4]))
		i += 4
		if tid < nfMinDataTemplateID || nfields == 0 || nfields > nfMaxTemplateFields {
			// Trailing padding is zeros; stop rather than treat as an error.
			break
		}
		if i+4*nfields > len(body) {
			p.metrics.parseErrors.Add(1)
			return
		}
		fields := make([]nfField, nfields)
		for n := 0; n < nfields; n++ {
			fields[n] = nfField{
				Type:   binary.BigEndian.Uint16(body[i : i+2]),
				Length: binary.BigEndian.Uint16(body[i+2 : i+4]),
			}
			i += 4
			if fields[n].Length == 0 || fields[n].Length == 0xffff {
				p.metrics.parseErrors.Add(1)
				return
			}
		}
		p.store.putData(nfTemplateKey{exporter: exporter, domain: domain, id: tid}, fields, now)
		p.metrics.templatesLearned.Add(1)
	}
}

func (p *nfParser) learnOptionTemplates(exporter [16]byte, domain uint32, body []byte, now time.Time) {
	i := 0
	for i+6 <= len(body) {
		tid := binary.BigEndian.Uint16(body[i : i+2])
		scopeLen := int(binary.BigEndian.Uint16(body[i+2 : i+4]))
		optLen := int(binary.BigEndian.Uint16(body[i+4 : i+6]))
		i += 6
		if tid < nfMinDataTemplateID || scopeLen%4 != 0 || optLen%4 != 0 {
			break
		}
		nScope := scopeLen / 4
		nOpt := optLen / 4
		if nScope+nOpt == 0 || nScope+nOpt > nfMaxTemplateFields || i+4*(nScope+nOpt) > len(body) {
			p.metrics.parseErrors.Add(1)
			return
		}
		scopes := make([]nfField, nScope)
		for n := 0; n < nScope; n++ {
			scopes[n] = nfField{
				Type:   binary.BigEndian.Uint16(body[i : i+2]),
				Length: binary.BigEndian.Uint16(body[i+2 : i+4]),
			}
			i += 4
		}
		options := make([]nfField, nOpt)
		for n := 0; n < nOpt; n++ {
			options[n] = nfField{
				Type:   binary.BigEndian.Uint16(body[i : i+2]),
				Length: binary.BigEndian.Uint16(body[i+2 : i+4]),
			}
			i += 4
		}
		p.store.putOption(nfTemplateKey{exporter: exporter, domain: domain, id: tid}, scopes, options, now)
		p.metrics.optionTemplates.Add(1)
	}
}

func (p *nfParser) decodeOptionRecords(exporter [16]byte, domain uint32, body []byte, tmpl nfOptionTemplate, now time.Time) {
	if tmpl.recordLen <= 0 {
		return
	}
	fields := append(append([]nfField(nil), tmpl.scopes...), tmpl.options...)
	for i := 0; i+tmpl.recordLen <= len(body); i += tmpl.recordLen {
		rec := body[i : i+tmpl.recordLen]
		var sampler uint32
		var rate uint64
		off := 0
		for _, f := range fields {
			val := rec[off : off+int(f.Length)]
			off += int(f.Length)
			switch f.Type {
			case nfFLOW_SAMPLER_ID:
				sampler = uint32(readNFUint(val))
			case nfSAMPLING_INTERVAL, nfFLOW_SAMPLER_RANDOM_INTERVAL:
				rate = readNFUint(val)
			}
		}
		if rate > 0 {
			p.store.putRate(nfSamplerKey{exporter: exporter, domain: domain, sampler: sampler}, rate, now)
		}
		p.metrics.optionRecords.Add(1)
	}
}

type nfDecoded struct {
	src, dst                   [16]byte
	hasSrc, hasDst             bool
	ipVer                      uint8
	proto                      uint32
	srcPort, dstPort           uint32
	bytes, packets             uint64
	inIf, outIf                uint32
	srcVLAN, dstVLAN           uint16
	tos, tcpFlags, ttl         uint8
	srcAS, dstAS               uint32
	srcMAC, dstMAC             [6]byte
	firstSwitched, lastSwitched uint32
	hasFirst                   bool
	samplerID                  uint32
}

func (p *nfParser) decodeDataRecords(
	body []byte,
	tmpl nfDataTemplate,
	exporter [16]byte,
	domain uint32,
	sysUp, unixSecs uint32,
	now time.Time,
) []flowingest.FlowRow {
	if tmpl.recordLen <= 0 {
		return nil
	}
	rows := make([]flowingest.FlowRow, 0, len(body)/tmpl.recordLen)
	for i := 0; i+tmpl.recordLen <= len(body); i += tmpl.recordLen {
		rec := p.readRecord(body[i:i+tmpl.recordLen], tmpl.fields)
		if !rec.hasSrc || !rec.hasDst {
			p.metrics.incompleteSkipped.Add(1)
			continue
		}
		rate := p.fallbackRate
		if optRate, ok := p.store.rate(exporter, domain, rec.samplerID, now); ok && optRate > 0 {
			if optRate != p.fallbackRate && p.fallbackRate != 1 {
				p.warnRate(exporter, domain, rec.samplerID, optRate)
			}
			rate = optRate
			p.metrics.rateFromOption.Add(1)
		} else {
			p.metrics.rateFromConfig.Add(1)
		}
		if rate == 0 {
			rate = 1
		}

		start := now
		if rec.hasFirst {
			start = flowStartTime(unixSecs, sysUp, rec.firstSwitched)
			if skew := start.Sub(now); skew > nfTimeSkewLimit*time.Second || skew < -nfTimeSkewLimit*time.Second {
				p.metrics.timeSkewFallback.Add(1)
				start = now
			}
		}

		etype := uint32(0x0800)
		ipVer := rec.ipVer
		if ipVer == 0 {
			if rec.src[4] != 0 || rec.src[5] != 0 {
				ipVer = 6
			} else {
				ipVer = 4
			}
		}
		if ipVer == 6 {
			etype = 0x86DD
		}

		row := flowingest.FlowRow{
			Date:            now,
			TimeInsertedNs:  now,
			TimeReceivedNs:  now,
			TimeFlowStartNs: start,
			SamplingRate:    rate,
			SamplerAddress:  exporter,
			SourceID:        p.sourceID,
			SrcAddr:         rec.src,
			DstAddr:         rec.dst,
			SrcAS:           rec.srcAS,
			DstAS:           rec.dstAS,
			SrcASN:          rec.srcAS,
			DstASN:          rec.dstAS,
			SrcVLAN:         rec.srcVLAN,
			DstVLAN:         rec.dstVLAN,
			Etype:           etype,
			Proto:           rec.proto,
			SrcPort:         rec.srcPort,
			DstPort:         rec.dstPort,
			Bytes:           rec.bytes * rate,
			Packets:         rec.packets * rate,
			SrcMAC:          rec.srcMAC,
			DstMAC:          rec.dstMAC,
			InIf:            rec.inIf,
			OutIf:           rec.outIf,
			TCPFlags:        rec.tcpFlags,
			IPTTL:           rec.ttl,
			IPTos:           rec.tos,
		}
		if p.classifier != nil {
			srcClass, dstClass, direction := p.classifier.ClassifyPair(
				rec.src, rec.dst, ipVer, rec.srcVLAN, rec.dstVLAN,
			)
			if d, ok := p.classifier.PortDirection(exporter, rec.inIf, rec.outIf); ok {
				direction = d
			}
			flowingest.ApplyEndpointClasses(&row, srcClass, dstClass, direction)
			p.classifier.AttachClients(&row)
		}
		rows = append(rows, row)
		p.metrics.recordsParsed.Add(1)
	}
	return rows
}

func (p *nfParser) readRecord(rec []byte, fields []nfField) nfDecoded {
	var out nfDecoded
	off := 0
	for _, f := range fields {
		if off+int(f.Length) > len(rec) {
			break
		}
		val := rec[off : off+int(f.Length)]
		off += int(f.Length)
		switch f.Type {
		case nfIPV4_SRC_ADDR:
			out.hasSrc = copyIPv4(&out.src, val)
			if out.ipVer == 0 {
				out.ipVer = 4
			}
		case nfIPV4_DST_ADDR:
			out.hasDst = copyIPv4(&out.dst, val)
			if out.ipVer == 0 {
				out.ipVer = 4
			}
		case nfIPV6_SRC_ADDR:
			out.hasSrc = copyIPv6(&out.src, val)
			out.ipVer = 6
		case nfIPV6_DST_ADDR:
			out.hasDst = copyIPv6(&out.dst, val)
			out.ipVer = 6
		case nfL4_SRC_PORT:
			out.srcPort = uint32(readNFUint(val))
		case nfL4_DST_PORT:
			out.dstPort = uint32(readNFUint(val))
		case nfPROTOCOL:
			out.proto = uint32(readNFUint(val))
		case nfIN_BYTES:
			out.bytes = readNFUint(val)
		case nfIN_PKTS:
			out.packets = readNFUint(val)
		case nfINPUT_SNMP:
			out.inIf = uint32(readNFUint(val))
		case nfOUTPUT_SNMP:
			out.outIf = uint32(readNFUint(val))
		case nfSRC_VLAN:
			out.srcVLAN = uint16(readNFUint(val))
		case nfDST_VLAN:
			out.dstVLAN = uint16(readNFUint(val))
		case nfSRC_TOS:
			out.tos = uint8(readNFUint(val))
		case nfTCP_FLAGS:
			out.tcpFlags = uint8(readNFUint(val))
		case nfMIN_TTL:
			out.ttl = uint8(readNFUint(val))
		case nfSRC_AS:
			out.srcAS = uint32(readNFUint(val))
		case nfDST_AS:
			out.dstAS = uint32(readNFUint(val))
		case nfFIRST_SWITCHED:
			out.firstSwitched = uint32(readNFUint(val))
			out.hasFirst = true
		case nfLAST_SWITCHED:
			out.lastSwitched = uint32(readNFUint(val))
		case nfIN_SRC_MAC, nfOUT_SRC_MAC:
			copyMAC(&out.srcMAC, val)
		case nfOUT_DST_MAC, nfIN_DST_MAC:
			copyMAC(&out.dstMAC, val)
		case nfIP_PROTOCOL_VERSION:
			out.ipVer = uint8(readNFUint(val))
		case nfFLOW_SAMPLER_ID:
			out.samplerID = uint32(readNFUint(val))
		}
	}
	return out
}

func flowStartTime(unixSecs, sysUp, firstSwitched uint32) time.Time {
	deltaMs := int64(sysUp - firstSwitched) // uint32 wrap is well-defined
	return time.Unix(int64(unixSecs), 0).UTC().Add(-time.Duration(deltaMs) * time.Millisecond)
}

func (p *nfParser) warnRate(exporter [16]byte, domain, sampler uint32, optionRate uint64) {
	key := fmt.Sprintf("%x/%d/%d", exporter[:4], domain, sampler)
	if _, loaded := p.rateWarn.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	p.metrics.rateMismatch.Add(1)
	if p.log != nil {
		ip, _ := agentIPString(exporter)
		p.log.Warn("netflow sampling rate differs from config",
			"exporter", ip,
			"domain", domain,
			"sampler_id", sampler,
			"option_rate", optionRate,
			"config_rate", p.fallbackRate,
		)
	}
}

func agentIPString(addr [16]byte) (string, bool) {
	if addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 &&
		addr[8] == 0 && addr[9] == 0 && addr[10] == 0 && addr[11] == 0 &&
		addr[12] == 0 && addr[13] == 0 && addr[14] == 0 && addr[15] == 0 {
		return net.IP(addr[:4]).String(), true
	}
	return net.IP(addr[:]).String(), true
}

func (p *nfParser) logMetrics(log *slog.Logger) {
	if p == nil {
		return
	}
	log.Info("netflow",
		"datagrams", p.metrics.datagrams.Load(),
		"records_parsed", p.metrics.recordsParsed.Load(),
		"parse_errors", p.metrics.parseErrors.Load(),
		"unknown_templates", p.metrics.unknownTemplates.Load(),
		"templates", p.store.dataCount(),
		"option_templates", p.metrics.optionTemplates.Load(),
		"option_records", p.metrics.optionRecords.Load(),
		"unsupported_v5", p.metrics.unsupportedV5.Load(),
		"unsupported_ipfix", p.metrics.unsupportedIPFIX.Load(),
		"rate_from_option", p.metrics.rateFromOption.Load(),
		"rate_from_config", p.metrics.rateFromConfig.Load(),
		"time_skew_fallback", p.metrics.timeSkewFallback.Load(),
		"incomplete_skipped", p.metrics.incompleteSkipped.Load(),
		"udp_queue_drops", p.metrics.udpQueueDrops.Load(),
	)
}

func (p *nfParser) receiverMetrics() flowingest.ReceiverMetrics {
	if p == nil {
		return flowingest.ReceiverMetrics{}
	}
	return flowingest.ReceiverMetrics{
		Datagrams:     p.metrics.datagrams.Load(),
		RecordsParsed: p.metrics.recordsParsed.Load(),
		ParseErrors:   p.metrics.parseErrors.Load(),
		UDPQueueDrops: p.metrics.udpQueueDrops.Load(),
	}
}

func (p *nfParser) addUDPQueueDrop() {
	p.metrics.udpQueueDrops.Add(1)
}
