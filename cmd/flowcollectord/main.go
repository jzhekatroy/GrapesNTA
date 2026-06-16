// flowcollectord — UDP flow collector (sFlow v5 MVP; NetFlow/IPFIX later).
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"xdpflowd/internal/flowingest"
)

func main() {
	cfg := loadConfig()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if !cfg.SFlowEnabled {
		log.Error("no listeners enabled (set -sflow-enabled or FC_SFLOW_ENABLED=1)")
		os.Exit(1)
	}
	if cfg.CHDSN == "" {
		log.Error("missing ClickHouse DSN (-ch-dsn / FC_CH_DSN)")
		os.Exit(1)
	}
	if cfg.SFlowSourceID == "" {
		log.Error("missing sflow source_id")
		os.Exit(1)
	}
	if cfg.CHSpoolMode != flowingest.SpoolOff && cfg.CHSpoolDir == "" {
		log.Error("ch-spool-mode requires ch-spool-dir")
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	classifier, err := flowingest.NewTrafficClassifier(ctx, log, flowingest.ClassifierConfig{
		Enabled: cfg.ClassifierEnabled,
		DSN:     cfg.CHDSN,
		Refresh: cfg.ClassifierRefresh,
		Tables: flowingest.ClassifierTables{
			BGPOrigins:    cfg.ClassifierBGPTable,
			IPASNPrefixes: cfg.ClassifierIPASNTable,
			L3Prefixes:    cfg.ClassifierL3PrefixesView,
			L2VLANs:       cfg.ClassifierL2VLANsView,
		},
	})
	if err != nil {
		log.Error("classifier init", "err", err)
		os.Exit(1)
	}
	if classifier != nil {
		defer classifier.Close()
	}

	delivery, err := flowingest.NewDelivery(log, flowingest.DeliveryConfig{
		DSN:                 cfg.CHDSN,
		Table:               cfg.CHTable,
		BatchSize:           cfg.CHBatchSize,
		FlushInterval:       cfg.CHFlushInterval,
		QueueSize:           cfg.CHQueueSize,
		SpoolMode:           cfg.CHSpoolMode,
		SpoolDir:            cfg.CHSpoolDir,
		SpoolSegSize:        cfg.CHSpoolSegSize,
		SpoolMaxBytes:       cfg.CHSpoolMaxBytes,
		SpoolFrameMaxRows:   cfg.CHSpoolFrameMaxRows,
		SpoolFsyncEvery:     cfg.CHSpoolFsyncEvery,
		SpoolShutdownDrain:  cfg.CHSpoolShutdownDrain,
		SpoolStallThreshold: cfg.CHSpoolStallThreshold,
		SpoolWriters:        cfg.CHWriters,
	})
	if err != nil {
		log.Error("clickhouse delivery init", "err", err)
		os.Exit(1)
	}
	defer func() {
		delivery.Close()
		delivery.LogMetrics()
	}()

	listener := newSflowListener(log, cfg.SFlowListen, cfg.SFlowSourceID, cfg.UDPReadBuffer, cfg.UDPReaders, cfg.UDPWorkers, cfg.UDPQueueSize, cfg.CHBatchSize, cfg.CHFlushInterval, delivery, classifier)

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.Run(ctx)
	}()

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	healthTicker := time.NewTicker(cfg.HealthInterval)
	defer healthTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("shutdown")
			return
		case err := <-errCh:
			if err != nil && ctx.Err() == nil {
				log.Error("listener stopped", "err", err)
				os.Exit(1)
			}
			return
		case <-ticker.C:
			listener.LogMetrics()
			delivery.LogMetrics()
		case <-healthTicker.C:
			h := delivery.HealthSnapshot()
			if h.InsertErrs > 0 || h.QueueDrops > 0 || h.LagSegments > 10 {
				log.Error("health",
					"mode", h.Mode,
					"insert_errs", h.InsertErrs,
					"queue_drops", h.QueueDrops,
					"lag_segments", h.LagSegments,
					"writer_lag_rows", h.RecordsSpooled-h.RecordsAcked,
				)
			}
		}
	}
}
