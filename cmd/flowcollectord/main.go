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
			BGPOrigins:        cfg.ClassifierBGPTable,
			IPASNPrefixes:     cfg.ClassifierIPASNTable,
			L3Prefixes:        cfg.ClassifierL3PrefixesView,
			L2VLANs:           cfg.ClassifierL2VLANsView,
			DirectionSettings: cfg.ClassifierDirectionSettingsView,
			InterfaceRoles:    cfg.ClassifierInterfaceRolesView,
		},
	})
	if err != nil {
		log.Error("classifier init", "err", err)
		os.Exit(1)
	}
	if classifier != nil {
		defer classifier.Close()
	}

	exclusions, err := flowingest.NewExclusionFilter(ctx, log, flowingest.ExclusionConfig{
		Enabled: cfg.ExclusionsEnabled,
		DSN:     cfg.CHDSN,
		Refresh: cfg.ExclusionsRefresh,
		Table:   cfg.ExclusionsView,
	})
	if err != nil {
		log.Error("flow exclusions init", "err", err)
		os.Exit(1)
	}
	if exclusions != nil {
		defer exclusions.Close()
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

	var healthReporter *flowingest.HealthReporter
	if cfg.CHHealthTable != "" {
		hr, err := flowingest.NewHealthReporter(log, flowingest.HealthReporterConfig{
			DSN:         cfg.CHDSN,
			Table:       cfg.CHHealthTable,
			CollectorID: cfg.CollectorID,
			SourceID:    cfg.SFlowSourceID,
			Daemon:      "flowcollectord",
		})
		if err != nil {
			log.Error("health reporter init", "err", err)
			os.Exit(1)
		}
		healthReporter = hr
		if healthReporter != nil {
			defer healthReporter.Close()
		}
	}

	listener := newSflowListener(log, cfg.SFlowListen, cfg.SFlowSourceID, cfg.UDPReadBuffer, cfg.UDPReaders, cfg.UDPWorkers, cfg.UDPQueueSize, cfg.CHBatchSize, cfg.CHFlushInterval, delivery, classifier, exclusions)

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.Run(ctx)
	}()

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	healthTicker := time.NewTicker(cfg.HealthInterval)
	defer healthTicker.Stop()

	var prevInsertErrs, prevQueueDrops, prevUDPDrops uint64

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
			insertErrsDelta := h.InsertErrs - prevInsertErrs
			queueDropsDelta := h.QueueDrops - prevQueueDrops
			rx := listener.receiverMetrics()
			udpDropsDelta := rx.UDPQueueDrops - prevUDPDrops
			if h.InsertErrs > 0 || h.QueueDrops > 0 || h.LagSegments > 10 || udpDropsDelta > 0 {
				log.Error("health",
					"mode", h.Mode,
					"insert_errs", h.InsertErrs,
					"queue_drops", h.QueueDrops,
					"lag_segments", h.LagSegments,
					"writer_lag_rows", h.RecordsSpooled-h.RecordsAcked,
					"udp_queue_drops", rx.UDPQueueDrops,
				)
			}
			if healthReporter != nil {
				_ = healthReporter.Write(ctx, flowingest.HealthWriteInput{
					Receiver:               rx,
					CH:                     h,
					Exclusions:             exclusions.Stats(),
					InsertErrsDelta:        insertErrsDelta,
					QueueDropsDelta:        queueDropsDelta,
					UDPQueueDropsDelta:     udpDropsDelta,
					LagSegmentsThreshold:   10,
					WriterLagRowsThreshold: 100000,
					DrainerAgeThreshold:    2 * time.Minute,
				})
			}
			prevInsertErrs = h.InsertErrs
			prevQueueDrops = h.QueueDrops
			prevUDPDrops = rx.UDPQueueDrops
		}
	}
}
