package main

import (
	"encoding/binary"
	"time"

	"xdpflowd/internal/flowingest"
)

// parseIPFIX reads RFC 7011 messages on the same UDP listener as NetFlow v9.
// One datagram may contain several messages; each is bounded by the Length field.
func (p *nfParser) parseIPFIX(d udpDatagram) []flowingest.FlowRow {
	b := d.b
	var rows []flowingest.FlowRow
	for len(b) >= ipfixHeaderLen {
		msgLen := int(binary.BigEndian.Uint16(b[2:4]))
		if msgLen < ipfixHeaderLen || msgLen > len(b) {
			p.metrics.parseErrors.Add(1)
			break
		}
		rows = append(rows, p.parseIPFIXMessage(d, b[:msgLen])...)
		b = b[msgLen:]
	}
	return rows
}

func (p *nfParser) parseIPFIXMessage(d udpDatagram, b []byte) []flowingest.FlowRow {
	exportTime := binary.BigEndian.Uint32(b[4:8])
	domain := binary.BigEndian.Uint32(b[12:16])
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
	off := ipfixHeaderLen
	for off+4 <= len(b) {
		setID := binary.BigEndian.Uint16(b[off : off+2])
		setLen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if setLen < 4 || off+setLen > len(b) {
			p.metrics.parseErrors.Add(1)
			break
		}
		body := b[off+4 : off+setLen]
		switch {
		case setID == ipfixTemplateSetID:
			p.learnIPFIXTemplates(exporter, domain, body, now)
		case setID == ipfixOptionsSetID:
			p.learnIPFIXOptionTemplates(exporter, domain, body, now)
		case setID >= nfMinDataTemplateID:
			key := nfTemplateKey{exporter: exporter, domain: domain, id: setID}
			if opt, ok := p.store.optionTemplate(key, now); ok {
				p.decodeOptionRecords(exporter, domain, body, opt, now)
				break
			}
			tmpl, ok := p.store.dataTemplate(key, now)
			if !ok {
				p.metrics.unknownTemplates.Add(1)
				break
			}
			// IPFIX has no sysUpTime. firstSwitched is ignored unless an
			// absolute start IE is present (handled in decodeDataRecords).
			decoded := p.decodeDataRecords(body, tmpl, exporter, domain, 0, exportTime, now)
			if len(decoded) > 0 {
				rows = append(rows, decoded...)
			}
		default:
			// Reserved set IDs: skip by length.
		}
		off += setLen
	}
	return rows
}

func readIPFIXSpec(body []byte, i int) (nfField, int, bool) {
	if i+4 > len(body) {
		return nfField{}, i, false
	}
	rawType := binary.BigEndian.Uint16(body[i : i+2])
	length := binary.BigEndian.Uint16(body[i+2 : i+4])
	i += 4
	f := nfField{Type: rawType & 0x7fff, Length: length}
	if rawType&0x8000 != 0 {
		if i+4 > len(body) {
			return nfField{}, i, false
		}
		f.Enterprise = binary.BigEndian.Uint32(body[i : i+4])
		i += 4
	}
	if f.Length == 0 {
		return nfField{}, i, false
	}
	return f, i, true
}

func (p *nfParser) learnIPFIXTemplates(exporter [16]byte, domain uint32, body []byte, now time.Time) {
	i := 0
	for i+4 <= len(body) {
		tid := binary.BigEndian.Uint16(body[i : i+2])
		nfields := int(binary.BigEndian.Uint16(body[i+2 : i+4]))
		i += 4
		if tid < nfMinDataTemplateID || nfields == 0 || nfields > nfMaxTemplateFields {
			break
		}
		fields := make([]nfField, nfields)
		for n := 0; n < nfields; n++ {
			f, next, ok := readIPFIXSpec(body, i)
			if !ok {
				p.metrics.parseErrors.Add(1)
				return
			}
			fields[n] = f
			i = next
		}
		p.store.putData(nfTemplateKey{exporter: exporter, domain: domain, id: tid}, fields, now)
		p.metrics.templatesLearned.Add(1)
	}
}

func (p *nfParser) learnIPFIXOptionTemplates(exporter [16]byte, domain uint32, body []byte, now time.Time) {
	i := 0
	for i+6 <= len(body) {
		tid := binary.BigEndian.Uint16(body[i : i+2])
		fieldCount := int(binary.BigEndian.Uint16(body[i+2 : i+4]))
		scopeCount := int(binary.BigEndian.Uint16(body[i+4 : i+6]))
		i += 6
		if tid < nfMinDataTemplateID || scopeCount == 0 || scopeCount > fieldCount || fieldCount > nfMaxTemplateFields {
			break
		}
		fields := make([]nfField, fieldCount)
		for n := 0; n < fieldCount; n++ {
			f, next, ok := readIPFIXSpec(body, i)
			if !ok {
				p.metrics.parseErrors.Add(1)
				return
			}
			fields[n] = f
			i = next
		}
		scopes := fields[:scopeCount]
		options := fields[scopeCount:]
		p.store.putOption(nfTemplateKey{exporter: exporter, domain: domain, id: tid}, scopes, options, now)
		p.metrics.optionTemplates.Add(1)
	}
}
