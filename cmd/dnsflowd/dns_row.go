//go:build linux

package main

import "time"

// DNSRow matches INSERT columns for default.dns_log (see deploy/clickhouse/dns_log.sql).
type DNSRow struct {
	Ts                 time.Time
	SourceID           string
	SamplerAddress     [16]byte
	ClientIP           [16]byte
	ServerIP           [16]byte
	ClientPort         uint16
	ServerPort         uint16
	IsResponse         uint8
	Transport          string
	TXID               uint16
	RCode              uint8
	Truncated          uint8
	RecursionDesired   uint8
	RecursionAvailable uint8
	QueryName          string
	QType              string
	QClass             string
	AnswersA           [][16]byte
	AnswersAAAA        [][16]byte
	AnswersCNAME       []string
	AnswersATTLs       []uint32
	AnswersAAAATTLs    []uint32
	AnswerTTLs         []uint32
	AnswerCount        uint16
	RawSize            uint16
}
