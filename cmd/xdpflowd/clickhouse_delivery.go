package main

import (
	"time"

	"xdpflowd/internal/flowingest"
)

type clickhouseDelivery struct {
	mapper flowRowMapper
	inner  *flowingest.Delivery
}

func (d *clickhouseDelivery) enqueue(flows []flowKV, receivedAt time.Time) {
	if d == nil || d.inner == nil || len(flows) == 0 {
		return
	}
	rows := flowRowsFromKV(flows, d.mapper, receivedAt)
	if len(rows) == 0 {
		return
	}
	d.inner.EnqueueRows(rows)
}

func (d *clickhouseDelivery) Close() {
	if d == nil || d.inner == nil {
		return
	}
	d.inner.Close()
}

func (d *clickhouseDelivery) LogMetrics() {
	if d == nil || d.inner == nil {
		return
	}
	d.inner.LogMetrics()
}

func (d *clickhouseDelivery) HealthSnapshot() flowingest.HealthSnapshot {
	if d == nil || d.inner == nil {
		return flowingest.HealthSnapshot{}
	}
	return d.inner.HealthSnapshot()
}
