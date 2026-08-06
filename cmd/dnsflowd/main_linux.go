//go:build linux

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"
)

func main() {
	iface := flag.String("iface", "eth0", "mirror interface for packet capture (libpcap)")
	sourceID := flag.String("source-id", "dns-default", "logical DNS observation point id written to dns_log/dns_answers.source_id")
	chDSN := flag.String("ch-dsn", "", `ClickHouse DSN, e.g. clickhouse://user:pass@host:9000/default`)
	chTable := flag.String("ch-table", "default.dns_log", "MergeTree table for raw DNS log INSERT")
	chAnswersTable := flag.String("ch-answers-table", "default.dns_answers", "MergeTree table for flattened DNS answers")
	chRawEnabled := flag.Bool("ch-raw-enabled", true, "write raw DNS rows to dns_log")
	chAnswersEnabled := flag.Bool("ch-answers-enabled", true, "write flattened DNS answers for flow enrichment")
	chBatchSize := flag.Int("ch-batch-size", 500, "legacy ClickHouse INSERT batch size (fallback for raw/answers batch)")
	chRawBatchSize := flag.Int("ch-raw-batch-size", 0, "raw dns_log batch size (0 uses -ch-batch-size)")
	chAnswersBatchSize := flag.Int("ch-answers-batch-size", 0, "dns_answers batch size (0 uses -ch-batch-size)")
	chFlush := flag.Duration("ch-flush-interval", time.Second, "ClickHouse flush interval")
	chQueue := flag.Int("ch-queue-size", 65536, "legacy bounded queue depth (fallback for raw queue when -ch-raw-queue-size is 0)")
	chRawQueueSize := flag.Int("ch-raw-queue-size", 0, "bounded raw dns_log queue depth in batches (0 uses -ch-queue-size)")
	chAnswersQueueSize := flag.Int("ch-answers-queue-size", 262144, "bounded dns_answers queue depth in batches")
	chRawWriters := flag.Int("ch-raw-writers", 1, "parallel ClickHouse writers for dns_log")
	chAnswersWriters := flag.Int("ch-answers-writers", 2, "parallel ClickHouse writers for dns_answers")
	captureBatch := flag.Int("capture-batch-size", 100, "capture-side row batch before send")
	captureFlush := flag.Duration("capture-flush-interval", 50*time.Millisecond, "capture-side max delay before send")
	chSampler := flag.String("ch-sampler-addr", "127.0.0.1", "sampler_address column (IPv4 / IPv6)")
	interval := flag.Duration("interval", 5*time.Second, "metrics log interval")
	healthInterval := flag.Duration("health-interval", time.Minute, "emit ERROR health log at most this often when DNS rows are dropped or writes lag")
	healthLagThreshold := flag.Uint64("health-lag-threshold", 100000, "ERROR when answers_queued - answers_written exceeds this many DNS answer rows")
	chRawAutoShed := flag.Bool("ch-raw-auto-shed-on-answers-lag", true, "pause raw dns_log enqueue when answers writer lag is high")
	chAnswersLagShed := flag.Uint64("ch-answers-lag-shed-threshold", 100000, "start raw shed when answers_writer_lag_rows exceeds this")
	chAnswersLagRecover := flag.Uint64("ch-answers-lag-recover-threshold", 50000, "resume raw after answers lag stays below this")
	chRawShedRecoverCooldown := flag.Duration("ch-raw-shed-recover-cooldown", 2*time.Minute, "how long answers lag must stay low before raw resumes")
	chAnswersDedupTTL := flag.Duration("ch-answers-dedup-ttl", 60*time.Second, "suppress duplicate dns_answers within this window (0 disables)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *chDSN == "" {
		log.Error("missing -ch-dsn")
		os.Exit(1)
	}
	if strings.TrimSpace(*sourceID) == "" {
		log.Error("source-id must not be empty")
		os.Exit(1)
	}
	*sourceID = strings.TrimSpace(*sourceID)
	if *healthInterval <= 0 {
		*healthInterval = time.Minute
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

	rawBatch := *chRawBatchSize
	if rawBatch < 1 {
		rawBatch = *chBatchSize
	}
	answersBatch := *chAnswersBatchSize
	if answersBatch < 1 {
		answersBatch = *chBatchSize
	}
	rawQueue := *chRawQueueSize
	if rawQueue < 1 {
		if *chQueue > 0 {
			rawQueue = *chQueue
		} else {
			rawQueue = 65536
		}
	}
	answersQueue := *chAnswersQueueSize
	if answersQueue < 1 {
		answersQueue = 262144
	}

	sink, err := newDNSClickhouseSink(log, *chDSN, clickhouseSinkConfig{
		RawEnabled:                 *chRawEnabled,
		RawTable:                   *chTable,
		RawBatchSize:               rawBatch,
		RawQueueSize:               rawQueue,
		RawWriters:                 *chRawWriters,
		AnswersEnabled:             *chAnswersEnabled,
		AnswersTable:               *chAnswersTable,
		AnswersBatchSize:           answersBatch,
		AnswersQueueSize:           answersQueue,
		AnswersWriters:             *chAnswersWriters,
		FlushInterval:              *chFlush,
		RawAutoShedOnAnswersLag:    *chRawAutoShed,
		AnswersLagShedThreshold:    *chAnswersLagShed,
		AnswersLagRecoverThreshold: *chAnswersLagRecover,
		RawShedRecoverCooldown:     *chRawShedRecoverCooldown,
		AnswersDedupTTL:            *chAnswersDedupTTL,
	})
	if err != nil {
		log.Error("clickhouse", "err", err)
		handle.Close()
		os.Exit(1)
	}
	defer sink.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var framesRead, emptyFrames, dnsRows, parseErrs, readTimeouts atomic.Uint64
	var ipv4UDP, ipv6UDP, ipv4TCP, ipv6TCP, otherL3 atomic.Uint64
	var readAttempts, readReturns atomic.Uint64
	var lastFrameLen, lastCaptureLen, lastWireLen, lastPayloadLen, lastPacketUnix, lastReadAttemptUnix, lastReadReturnUnix atomic.Uint64

	tick := time.NewTicker(*interval)
	defer tick.Stop()
	healthTick := time.NewTicker(*healthInterval)
	defer healthTick.Stop()

	var metricsWG sync.WaitGroup
	metricsWG.Add(1)
	go func() {
		defer metricsWG.Done()
		var prevFramesRead, prevDNSRows uint64
		var prevIPv4UDP, prevIPv6UDP, prevIPv4TCP, prevIPv6TCP, prevOther uint64
		var prevRawQueueDrops, prevAnswersQueueDrops, prevRawInsertErrs, prevAnswersInsertErrs uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				sink.LogMetrics()
				curFramesRead := framesRead.Load()
				curDNSRows := dnsRows.Load()
				curIPv4UDP := ipv4UDP.Load()
				curIPv6UDP := ipv6UDP.Load()
				curIPv4TCP := ipv4TCP.Load()
				curIPv6TCP := ipv6TCP.Load()
				curOther := otherL3.Load()
				dIPv4UDP := curIPv4UDP - prevIPv4UDP
				dIPv6UDP := curIPv6UDP - prevIPv6UDP
				dIPv4TCP := curIPv4TCP - prevIPv4TCP
				dIPv6TCP := curIPv6TCP - prevIPv6TCP
				dOther := curOther - prevOther
				classifiedDelta := dIPv4UDP + dIPv6UDP + dIPv4TCP + dIPv6TCP + dOther
				// Blind = frames we still do not parse into dns_log (TCP + other).
				blindDelta := dIPv4TCP + dIPv6TCP + dOther
				var blindPct float64
				if classifiedDelta > 0 {
					blindPct = 100 * float64(blindDelta) / float64(classifiedDelta)
				}
				log.Info("dnsflowd capture", "iface", *iface,
					"frames_read", curFramesRead,
					"frames_delta", curFramesRead-prevFramesRead,
					"dns_rows", curDNSRows,
					"dns_rows_delta", curDNSRows-prevDNSRows,
					"empty_frames", emptyFrames.Load(),
					"ipv4_udp", curIPv4UDP,
					"ipv4_udp_delta", dIPv4UDP,
					"ipv6_udp", curIPv6UDP,
					"ipv6_udp_delta", dIPv6UDP,
					"ipv4_tcp", curIPv4TCP,
					"ipv4_tcp_delta", dIPv4TCP,
					"ipv6_tcp", curIPv6TCP,
					"ipv6_tcp_delta", dIPv6TCP,
					"other_l3", curOther,
					"other_l3_delta", dOther,
					"blind_delta", blindDelta,
					"blind_pct", blindPct,
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
				prevIPv4UDP = curIPv4UDP
				prevIPv6UDP = curIPv6UDP
				prevIPv4TCP = curIPv4TCP
				prevIPv6TCP = curIPv6TCP
				prevOther = curOther
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
			case <-healthTick.C:
				curRawQueueDrops := sink.RawQueueDrops()
				curAnswersQueueDrops := sink.AnswersQueueDrops()
				curRawInsertErrs := sink.rawInsertErrs.Load()
				curAnswersInsertErrs := sink.answersInsertErrs.Load()
				curQueueDrops := sink.queueDrops.Load()
				rawWriterLag := sink.RawWriterLag()
				answersWriterLag := sink.AnswersWriterLag()
				rawQueueDropsDelta := curRawQueueDrops - prevRawQueueDrops
				answersQueueDropsDelta := curAnswersQueueDrops - prevAnswersQueueDrops
				rawInsertErrsDelta := curRawInsertErrs - prevRawInsertErrs
				answersInsertErrsDelta := curAnswersInsertErrs - prevAnswersInsertErrs
				queueDropsDelta := rawQueueDropsDelta + answersQueueDropsDelta
				degraded := answersQueueDropsDelta > 0 ||
					rawQueueDropsDelta > 0 ||
					rawInsertErrsDelta > 0 ||
					answersInsertErrsDelta > 0 ||
					answersWriterLag > *healthLagThreshold
				if degraded {
					log.Error("dnsflowd health degraded",
						"raw_policy", sink.rawShed.RawPolicyLabel(),
						"raw_shed_active", sink.rawShed.ShedActive(),
						"raw_shed_due_answers_lag_total", sink.rawShed.ShedTotal(),
						"raw_queue_drops_delta", rawQueueDropsDelta,
						"raw_queue_drops_total", curRawQueueDrops,
						"answers_queue_drops_delta", answersQueueDropsDelta,
						"answers_queue_drops_total", curAnswersQueueDrops,
						"queue_drops_delta", queueDropsDelta,
						"queue_drops_total", curQueueDrops,
						"raw_insert_errs_delta", rawInsertErrsDelta,
						"raw_insert_errs_total", curRawInsertErrs,
						"answers_insert_errs_delta", answersInsertErrsDelta,
						"answers_insert_errs_total", curAnswersInsertErrs,
						"insert_errs_delta", rawInsertErrsDelta,
						"insert_errs_total", sink.insertErrs.Load(),
						"raw_writer_lag_rows", rawWriterLag,
						"answers_writer_lag_rows", answersWriterLag,
						"writer_lag_rows", answersWriterLag,
						"health_lag_threshold", *healthLagThreshold,
						"records_queued", sink.recordsQueued.Load(),
						"records_written", sink.recordsWritten.Load(),
						"answers_written", sink.answersWritten.Load(),
						"raw_queue_depth_batches", sink.RawQueueDepth(),
						"answers_queue_depth_batches", sink.AnswersQueueDepth(),
					)
				}
				prevRawQueueDrops = curRawQueueDrops
				prevAnswersQueueDrops = curAnswersQueueDrops
				prevRawInsertErrs = curRawInsertErrs
				prevAnswersInsertErrs = curAnswersInsertErrs
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

			kind, srcIP, dstIP, sport, dport, payload := classifyPort53Frame(data)
			switch kind {
			case dnsFrameIPv4UDP:
				ipv4UDP.Add(1)
			case dnsFrameIPv6UDP:
				ipv6UDP.Add(1)
			case dnsFrameIPv4TCP:
				ipv4TCP.Add(1)
				continue
			case dnsFrameIPv6TCP:
				ipv6TCP.Add(1)
				continue
			default:
				otherL3.Add(1)
				continue
			}
			if len(payload) == 0 || (sport != 53 && dport != 53) {
				// Counted in ipv4_udp/ipv6_udp for ratios; nothing to parse.
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
			row.SourceID = *sourceID
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
		"source_id", *sourceID,
		"bpf_filter", "port 53",
		"parse_path", "ipv4_udp+ipv6_udp",
		"ch_raw_enabled", *chRawEnabled,
		"ch_table", *chTable,
		"ch_answers_enabled", *chAnswersEnabled,
		"ch_answers_table", *chAnswersTable,
		"ch_raw_batch_size", rawBatch,
		"ch_answers_batch_size", answersBatch,
		"ch_raw_queue_size", rawQueue,
		"ch_answers_queue_size", answersQueue,
		"ch_raw_writers", *chRawWriters,
		"ch_answers_writers", *chAnswersWriters,
		"capture_batch_size", *captureBatch,
		"capture_flush_interval", *captureFlush,
		"capture", "libpcap",
		"health_interval", *healthInterval,
		"health_lag_threshold", *healthLagThreshold,
		"ch_raw_auto_shed_on_answers_lag", *chRawAutoShed,
		"ch_answers_lag_shed_threshold", *chAnswersLagShed,
		"ch_answers_lag_recover_threshold", *chAnswersLagRecover,
		"ch_raw_shed_recover_cooldown", *chRawShedRecoverCooldown,
		"ch_answers_dedup_ttl", *chAnswersDedupTTL,
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
