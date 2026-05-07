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

	"golang.org/x/sys/unix"
)

func main() {
	iface := flag.String("iface", "eth0", "mirror interface for AF_PACKET capture")
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

	fd, err := openCapture(*iface)
	if err != nil {
		log.Error("open capture", "iface", *iface, "err", err)
		os.Exit(1)
	}

	sink, err := newDNSClickhouseSink(log, *chDSN, *chTable, *chBatchSize, *chFlush, *chQueue)
	if err != nil {
		log.Error("clickhouse", "err", err)
		_ = unix.Close(fd)
		os.Exit(1)
	}
	defer sink.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var packetsSeen, parseErrs atomic.Uint64

	tick := time.NewTicker(*interval)
	defer tick.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				sink.LogMetrics()
				log.Info("dnsflowd capture", "iface", *iface,
					"packets_seen", packetsSeen.Load(),
					"parse_errs", parseErrs.Load(),
				)
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				if ctx.Err() != nil {
					return
				}
				log.Warn("read", "err", err)
				return
			}
			if n <= 0 {
				continue
			}
			packetsSeen.Add(1)

			frame := buf[:n]
			srcIP, dstIP, sport, dport, payload, ok := parseIPv4UDPPayload(frame)
			if !ok || len(payload) == 0 {
				continue
			}

			row, err := parseDNS(payload, srcIP, dstIP, sport, dport, sampler, time.Now())
			if err != nil {
				parseErrs.Add(1)
				continue
			}
			sink.EnqueueRows([]DNSRow{row})
		}
	}()

	log.Info("dnsflowd started", "iface", *iface, "ch_table", *chTable)

	<-ctx.Done()
	log.Info("dnsflowd shutting down")
	_ = unix.Close(fd)
	wg.Wait()
}
