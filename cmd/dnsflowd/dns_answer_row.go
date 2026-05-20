//go:build linux

package main

import "time"

// DNSAnswerRow matches INSERT columns for default.dns_answers (see deploy/clickhouse/dns_answers.sql).
type DNSAnswerRow struct {
	Ts             time.Time
	SamplerAddress [16]byte
	ClientIP       [16]byte
	ServerIP       [16]byte
	ClientPort     uint16
	ServerPort     uint16
	QueryName      string
	QType          string
	QClass         string
	AnswerType     string
	AnswerIP       [16]byte
	TTL            uint32
	RCode          uint8
	TXID           uint16
	Transport      string
}

// dnsAnswersFromRow expands a parsed DNS response into flat answer rows for flow enrichment.
// Only successful responses (rcode=0) with A/AAAA answers are emitted.
func dnsAnswersFromRow(row DNSRow) []DNSAnswerRow {
	if row.IsResponse == 0 || row.RCode != 0 {
		return nil
	}
	n := len(row.AnswersA) + len(row.AnswersAAAA)
	if n == 0 {
		return nil
	}
	out := make([]DNSAnswerRow, 0, n)
	base := DNSAnswerRow{
		Ts:             row.Ts,
		SamplerAddress: row.SamplerAddress,
		ClientIP:       row.ClientIP,
		ServerIP:       row.ServerIP,
		ClientPort:     row.ClientPort,
		ServerPort:     row.ServerPort,
		QueryName:      row.QueryName,
		QType:          row.QType,
		QClass:         row.QClass,
		RCode:          row.RCode,
		TXID:           row.TXID,
		Transport:      row.Transport,
	}
	for i, ip := range row.AnswersA {
		r := base
		r.AnswerType = "A"
		r.AnswerIP = ip
		if i < len(row.AnswersATTLs) {
			r.TTL = row.AnswersATTLs[i]
		}
		out = append(out, r)
	}
	for i, ip := range row.AnswersAAAA {
		r := base
		r.AnswerType = "AAAA"
		r.AnswerIP = ip
		if i < len(row.AnswersAAAATTLs) {
			r.TTL = row.AnswersAAAATTLs[i]
		}
		out = append(out, r)
	}
	return out
}
