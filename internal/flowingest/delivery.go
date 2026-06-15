package flowingest

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// HealthSnapshot aggregates ClickHouse delivery counters for health checks.
type HealthSnapshot struct {
	RecordsQueued      uint64
	RecordsWritten     uint64
	RecordsSpooled     uint64
	RecordsAcked       uint64
	InsertErrs         uint64
	QueueDrops         uint64
	LagSegments        int64
	DrainerProgressAge time.Duration
	Mode               string
}

// DeliveryConfig wires direct sink or durable spool pipeline.
type DeliveryConfig struct {
	DSN              string
	Table            string
	BatchSize        int
	FlushInterval    time.Duration
	QueueSize        int
	SpoolMode        SpoolMode
	SpoolDir         string
	SpoolSegSize     int64
	SpoolMaxBytes    int64
	SpoolFrameMaxRows int
	SpoolFsyncEvery  time.Duration
	SpoolShutdownDrain time.Duration
	SpoolStallThreshold time.Duration
	SpoolWriters     int
	AllowedSourceID  string
}

// Delivery accepts ready FlowRow batches for ClickHouse ingest.
type Delivery struct {
	log    *slog.Logger
	mode   SpoolMode
	spool  *SpoolPipeline
	direct *Sink
}

func NewDelivery(log *slog.Logger, cfg DeliveryConfig) (*Delivery, error) {
	if strings.TrimSpace(cfg.DSN) == "" {
		return nil, fmt.Errorf("clickhouse DSN is required")
	}
	if strings.TrimSpace(cfg.Table) == "" {
		return nil, fmt.Errorf("clickhouse table is required")
	}
	d := &Delivery{log: log, mode: cfg.SpoolMode}
	if cfg.SpoolMode != SpoolOff {
		sp, err := NewSpoolPipeline(log,
			strings.TrimSpace(cfg.DSN), strings.TrimSpace(cfg.Table),
			strings.TrimSpace(cfg.SpoolDir),
			cfg.SpoolSegSize,
			cfg.SpoolMaxBytes,
			cfg.SpoolFrameMaxRows,
			cfg.SpoolFsyncEvery,
			cfg.SpoolShutdownDrain,
			cfg.SpoolStallThreshold,
			cfg.SpoolMode,
			cfg.SpoolWriters,
			cfg.AllowedSourceID,
		)
		if err != nil {
			return nil, err
		}
		d.spool = sp
		return d, nil
	}
	sink, err := NewSink(log, strings.TrimSpace(cfg.DSN), strings.TrimSpace(cfg.Table),
		cfg.BatchSize, cfg.FlushInterval, cfg.QueueSize)
	if err != nil {
		return nil, err
	}
	d.direct = sink
	return d, nil
}

func (d *Delivery) EnqueueRows(rows []FlowRow) {
	if d == nil || len(rows) == 0 {
		return
	}
	if d.spool != nil {
		if err := d.spool.Append(rows); err != nil {
			if d.mode == SpoolRequired {
				d.log.Error("clickhouse spool append failed (required mode)", "err", err)
				os.Exit(1)
			}
			d.log.Warn("clickhouse spool append failed", "err", err)
		}
		return
	}
	if d.direct != nil {
		d.direct.EnqueueRows(rows)
	}
}

func (d *Delivery) Close() {
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

func (d *Delivery) LogMetrics() {
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

func (d *Delivery) HealthSnapshot() HealthSnapshot {
	if d == nil {
		return HealthSnapshot{}
	}
	if d.spool != nil {
		s := d.spool.HealthSnapshot()
		s.Mode = "spool"
		return s
	}
	if d.direct != nil {
		s := d.direct.HealthSnapshot()
		s.Mode = "direct"
		return s
	}
	return HealthSnapshot{}
}
