//go:build linux

package main

import (
	"context"
	"encoding/hex"
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
	chQueue := flag.Int("ch-queue-size", 4096, "bounded queue depth (drops on overflow)")
	captureBatch := flag.Int("capture-batch-size", 100, "capture-side row batch before send")
	captureFlush := flag.Duration("capture-flush-interval", 50*time.Millisecond, "capture-side max delay before send")
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

	var framesRead, emptyFrames, nonIPv4UDP, nonDNS, dnsRows, parseErrs, readTimeouts atomic.Uint64
	var readAttempts, readReturns atomic.Uint64
	var lastFrameLen, lastCaptureLen, lastWireLen, lastPayloadLen, lastPacketUnix, lastReadAttemptUnix, lastReadReturnUnix atomic.Uint64

	tick := time.NewTicker(*interval)
	defer tick.Stop()

	var metricsWG sync.WaitGroup
	metricsWG.Add(1)
	go func() {
		defer metricsWG.Done()
		var prevFramesRead, prevDNSRows uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				sink.LogMetrics()
				curFramesRead := framesRead.Load()
				curDNSRows := dnsRows.Load()
				log.Info("dnsflowd capture", "iface", *iface,
					"frames_read", curFramesRead,
					"frames_delta", curFramesRead-prevFramesRead,
					"dns_rows", curDNSRows,
					"dns_rows_delta", curDNSRows-prevDNSRows,
					"empty_frames", emptyFrames.Load(),
					"non_ipv4_udp", nonIPv4UDP.Load(),
					"non_dns", nonDNS.Load(),
					"parse_errs", parseErrs.Load(),
					"read_timeouts", readTimeouts.Load(),
					"read_attempts", readAttempts.Load(),
					"read_returns", readReturns.Load(),
					"last_frame_len", lastFrameLen.Load(),
					"last_capture_len", lastCaptureLen.Load(),
					"last_wire_len", lastWireLen.Load(),
					"last_payload_len", lastPayloadLen.Load(),
					"last_packet_unix", lastPacketUnix.Load(),
					"last_read_attempt_unix", lastReadAttemptUnix.Load(),
					"last_read_return_unix", lastReadReturnUnix.Load(),
				)
				if readAttempts.Load() > readReturns.Load() && curFramesRead == prevFramesRead {
					log.Warn("dnsflowd capture stall",
						"iface", *iface,
						"frames_read", curFramesRead,
						"read_timeouts", readTimeouts.Load(),
						"read_attempts", readAttempts.Load(),
						"read_returns", readReturns.Load(),
						"last_read_attempt_unix", lastReadAttemptUnix.Load(),
						"last_read_return_unix", lastReadReturnUnix.Load(),
						"hint", "ReadPacketData call is stuck; pcap stats are intentionally not called concurrently",
					)
				}
				prevFramesRead = curFramesRead
				prevDNSRows = curDNSRows
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		batchCap := *captureBatch
		if batchCap < 1 {
			batchCap = 1
		}
		pending := make([]DNSRow, 0, batchCap)
		var pendingSince time.Time
		flushPending := func() {
			if len(pending) == 0 {
				return
			}
			sink.EnqueueRows(pending)
			pending = pending[:0]
			pendingSince = time.Time{}
		}
		defer flushPending()
		for {
			if ctx.Err() != nil {
				return
			}
			if len(pending) > 0 && time.Since(pendingSince) >= *captureFlush {
				flushPending()
			}
			readAttempts.Add(1)
			lastReadAttemptUnix.Store(uint64(time.Now().Unix()))
			data, ci, err := handle.ReadPacketData()
			readReturns.Add(1)
			lastReadReturnUnix.Store(uint64(time.Now().Unix()))
			if err != nil {
				if err == pcap.NextErrorTimeoutExpired {
					readTimeouts.Add(1)
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
			if len(data) == 0 {
				emptyFrames.Add(1)
				continue
			}
			lastFrameLen.Store(uint64(len(data)))
			lastCaptureLen.Store(uint64(ci.CaptureLength))
			lastWireLen.Store(uint64(ci.Length))

			ts := ci.Timestamp
			if ts.IsZero() {
				ts = time.Now()
			}
			lastPacketUnix.Store(uint64(ts.Unix()))

			srcIP, dstIP, sport, dport, payload, ok := parseIPv4UDPPayload(data)
			if !ok || len(payload) == 0 {
				nonIPv4UDP.Add(1)
				continue
			}
			if sport != 53 && dport != 53 {
				nonDNS.Add(1)
				continue
			}
			lastPayloadLen.Store(uint64(len(payload)))

			row, err := parseDNS(payload, srcIP, dstIP, sport, dport, sampler, ts.UTC())
			if err != nil {
				if parseErrs.Load() < 5 {
					dump := payload
					if len(dump) > 256 {
						dump = dump[:256]
					}
					log.Warn("dnsflowd parse error",
						"err", err,
						"payload_len", len(payload),
						"sport", sport,
						"dport", dport,
						"hex", hex.EncodeToString(dump),
					)
				}
				parseErrs.Add(1)
				continue
			}
			dnsRows.Add(1)
			if dnsRows.Load() <= 10 {
				log.Info("dnsflowd dns sample",
					"ts", row.Ts,
					"query_name", row.QueryName,
					"qtype", row.QType,
					"is_response", row.IsResponse,
					"client_port", row.ClientPort,
					"server_port", row.ServerPort,
					"answer_count", row.AnswerCount,
					"payload_len", len(payload),
				)
			}
			if len(pending) == 0 {
				pendingSince = time.Now()
			}
			pending = append(pending, row)
			if len(pending) >= batchCap {
				flushPending()
			}
		}
	}()

	log.Info("dnsflowd started",
		"iface", *iface,
		"ch_table", *chTable,
		"capture", "libpcap",
		"datalink", handle.LinkType().String(),
		"datalink_name", handle.LinkTypeName(),
	)

	<-ctx.Done()
	log.Info("dnsflowd shutting down")
	tick.Stop()
	metricsWG.Wait()
	handle.Close()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		log.Warn("dnsflowd capture goroutine did not stop after pcap close")
	}
}
