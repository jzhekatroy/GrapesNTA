package main

import (
	"log/slog"
	"os"
	"time"
)

// clickhouseDelivery routes flowKV batches to either a durable spool pipeline or a direct sink.
type clickhouseDelivery struct {
	log    *slog.Logger
	mapper flowRowMapper
	mode   chSpoolMode

	spool  *spoolClickhousePipeline
	direct *clickhouseSink
}

func (d *clickhouseDelivery) enqueue(flows []flowKV, receivedAt time.Time) {
	if d == nil || len(flows) == 0 {
		return
	}
	rows := flowRowsFromKV(flows, d.mapper, receivedAt)
	if len(rows) == 0 {
		return
	}
	if d.spool != nil {
		if err := d.spool.Append(rows); err != nil {
			if d.mode == chSpoolRequired {
				d.log.Error("clickhouse spool append failed (required mode)", "err", err)
				os.Exit(1)
			}
			d.log.Warn("clickhouse spool append failed", "err", err)
		}
		return
	}
	d.direct.EnqueueRows(rows)
}

func (d *clickhouseDelivery) Close() {
	if d == nil {
		return
	}
	if d.spool != nil {
		d.spool.Close()
		return
	}
	if d.direct != nil {
		d.direct.Close()
	}
}

func (d *clickhouseDelivery) LogMetrics() {
	if d == nil {
		return
	}
	if d.spool != nil {
		d.spool.LogMetrics()
		return
	}
	if d.direct != nil {
		d.direct.LogMetrics()
	}
}
