//go:build linux

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"
)

func main() {
	iface := flag.String("iface", "eth0", "mirror interface for packet capture (libpcap)")
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

	handle, err := openPacketCapture(*iface)
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
				stats, stErr := handle.Stats()
				ll := log.Info
				if stErr != nil {
					ll = log.Warn
				}
				ll("dnsflowd capture", "iface", *iface,
					"frames_read", framesRead.Load(),
					"dns_rows", dnsRows.Load(),
					"parse_errs", parseErrs.Load(),
					"pcap_received", stats.packetsReceived,
					"pcap_dropped", stats.packetsDropped,
					"pcap_if_dropped", stats.packetsIfDropped,
					"pcap_stats_err", stErr,
				)
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			if ctx.Err() != nil {
				return
			}
			data, ci, err := handle.ReadPacketData()
			if err != nil {
				if err == pcap.NextErrorTimeoutExpired {
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

			row, err := parseDNS(payload, srcIP, dstIP, sport, dport, sampler, ts.UTC())
			if err != nil {
				parseErrs.Add(1)
				continue
			}
			dnsRows.Add(1)
			sink.EnqueueRows([]DNSRow{row})
		}
	}()

	log.Info("dnsflowd started", "iface", *iface, "ch_table", *chTable, "capture", "libpcap")

	<-ctx.Done()
	log.Info("dnsflowd shutting down")
	tick.Stop()
	metricsWG.Wait()
	// Capture exits within the pcap timeout (~250ms) via timeout + ctx.Err() check.
	wg.Wait()
	handle.Close()
}
