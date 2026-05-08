//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket/afpacket"
)

func main() {
	iface := flag.String("iface", "eth0", "mirror interface for packet capture (TPACKET_V3)")
	chDSN := flag.String("ch-dsn", "", `ClickHouse DSN, e.g. clickhouse://user:pass@host:9000/default`)
	chTable := flag.String("ch-table", "default.dns_log", "MergeTree table for DNS INSERT")
	chBatchSize := flag.Int("ch-batch-size", 500, "ClickHouse INSERT batch size")
	chFlush := flag.Duration("ch-flush-interval", time.Second, "ClickHouse flush interval")
	chQueue := flag.Int("ch-queue-size", 64, "bounded queue depth (drops on overflow)")
	chSampler := flag.String("ch-sampler-addr", "127.0.0.1", "sampler_address column (IPv4 / IPv6)")
	interval := flag.Duration("interval", 5*time.Second, "metrics log interval")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *chDSN == "" {
		log.Error("missing -ch-dsn")
		os.Exit(1)
	}

	sampler, err := parseSamplerAddress(*chSampler)
	if err != nil {
		log.Error("sampler address", "err", err)
		os.Exit(1)
	}

	handle, err := openRingCapture(*iface)
	if err != nil {
		log.Error("open capture", "iface", *iface, "err", err)
		os.Exit(1)
	}

	sink, err := newDNSClickhouseSink(log, *chDSN, *chTable, *chBatchSize, *chFlush, *chQueue)
	if err != nil {
		log.Error("clickhouse", "err", err)
		handle.Close()
		os.Exit(1)
	}
	defer sink.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var framesRead, dnsRows, parseErrs atomic.Uint64

	tick := time.NewTicker(*interval)
	defer tick.Stop()

	var metricsWG sync.WaitGroup
	metricsWG.Add(1)
	go func() {
		defer metricsWG.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				sink.LogMetrics()
				_, v3, stErr := handle.SocketStats()
				ll := log.Info
				if stErr != nil {
					ll = log.Warn
				}
				ll("dnsflowd capture", "iface", *iface,
					"frames_read", framesRead.Load(),
					"dns_rows", dnsRows.Load(),
					"parse_errs", parseErrs.Load(),
					"kernel_tp_packets", v3.Packets(),
					"kernel_tp_drops", v3.Drops(),
					"kernel_tp_freeze_q", v3.QueueFreezes(),
					"socket_stats_err", stErr,
				)
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			data, ci, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				if errors.Is(err, afpacket.ErrTimeout) {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				if ctx.Err() != nil {
					return
				}
				log.Error("read packet (capture stopped)", "err", err)
				cancel() // make systemd restart us instead of running headless
				return
			}
			framesRead.Add(1)

			ts := ci.Timestamp
			if ts.IsZero() {
				ts = time.Now()
			}

			srcIP, dstIP, sport, dport, payload, ok := parseIPv4UDPPayload(data)
			if !ok || len(payload) == 0 {
				continue
			}
			if sport != 53 && dport != 53 {
				continue
			}

			// Zero-copy slice is invalid after the next Read; copy DNS payload for the parser.
			payloadCopy := append([]byte(nil), payload...)
			row, err := parseDNS(payloadCopy, srcIP, dstIP, sport, dport, sampler, ts.UTC())
			if err != nil {
				parseErrs.Add(1)
				continue
			}
			dnsRows.Add(1)
			sink.EnqueueRows([]DNSRow{row})
		}
	}()

	log.Info("dnsflowd started", "iface", *iface, "ch_table", *chTable, "capture", "TPACKET_V3")

	<-ctx.Done()
	log.Info("dnsflowd shutting down")
	tick.Stop()
	metricsWG.Wait()
	// Wait for capture to leave ZeroCopyReadPacketData() before munmap'ing the ring.
	// Capture exits within OptPollTimeout (~250ms) via ErrTimeout + ctx.Err() check.
	wg.Wait()
	handle.Close()
}
