package main

import (
	"log/slog"
	"net"
	"time"

	"xdpflowd/internal/flowingest"
)

type udpDatagram struct {
	b          []byte
	receivedAt time.Time
	src        net.IP
}

type protocolParser interface {
	parse(d udpDatagram) []flowingest.FlowRow
	logMetrics(log *slog.Logger)
	receiverMetrics() flowingest.ReceiverMetrics
	addUDPQueueDrop()
}

type sflowParser struct {
	sourceID   string
	classifier *flowingest.TrafficClassifier
	metrics    sflowMetrics
}

func (p *sflowParser) parse(d udpDatagram) []flowingest.FlowRow {
	return parseSFlowV5(d.b, d.receivedAt, p.sourceID, p.classifier, nil, &p.metrics)
}

func (p *sflowParser) logMetrics(log *slog.Logger) {
	if p == nil {
		return
	}
	log.Info("sflow",
		"datagrams", p.metrics.datagrams.Load(),
		"flow_samples", p.metrics.flowSamples.Load(),
		"records_parsed", p.metrics.recordsParsed.Load(),
		"non_ip_skipped", p.metrics.nonIPSkipped.Load(),
		"counter_skipped", p.metrics.counterSkipped.Load(),
		"parse_errors", p.metrics.parseErrors.Load(),
		"unknown_samples", p.metrics.unknownSamples.Load(),
		"udp_queue_drops", p.metrics.udpQueueDrops.Load(),
	)
}

func (p *sflowParser) receiverMetrics() flowingest.ReceiverMetrics {
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

func (p *sflowParser) addUDPQueueDrop() {
	p.metrics.udpQueueDrops.Add(1)
}
