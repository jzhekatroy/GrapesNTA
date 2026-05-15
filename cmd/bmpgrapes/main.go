package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// MVP BMP collector: listens for incoming BMP TCP sessions from routers, parses
// peer state and route monitoring messages, writes normalized rows into
// ClickHouse (default.bmp_peers, default.bmp_route_events).

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:5000", "BMP TCP listen address")
	chDSN := flag.String("ch-dsn", "", "ClickHouse DSN clickhouse://user:pass@host:9000/default")
	eventsTable := flag.String("ch-events-table", "default.bmp_route_events", "ClickHouse table for route events")
	peersTable := flag.String("ch-peers-table", "default.bmp_peers", "ClickHouse table for peer events")
	batchSize := flag.Int("ch-batch-size", 1000, "ClickHouse INSERT batch size")
	flushInt := flag.Duration("ch-flush-interval", time.Second, "ClickHouse flush interval")
	queueSize := flag.Int("ch-queue-size", 4096, "bounded queue depth")
	queueModeStr := flag.String("ch-queue-mode", "block", "queue overflow behaviour: block (default, propagates TCP back-pressure to router; no data loss) | drop (legacy, discards batches when queue is full)")
	allowlistFlag := flag.String("allow-routers", "", "optional comma-separated list of allowed router IPs (empty = allow all)")
	maxMsgSize := flag.Int("max-message-bytes", 65535, "maximum BMP message size accepted (RFC 7854 caps at 4 GiB; routers stay under 64 KiB)")
	metricsInterval := flag.Duration("interval", 10*time.Second, "metrics log interval")
	logLevel := flag.String("log-level", "info", "log level: debug | info | warn | error")
	logFormat := flag.String("log-format", "text", "log format: text | json")
	updateSampleN := flag.Uint64("log-update-samples", 10, "how many BGP UPDATEs per session to log at Info level for visibility")
	flag.Parse()

	log := newLogger(*logLevel, *logFormat)

	if *chDSN == "" {
		log.Error("missing -ch-dsn")
		os.Exit(1)
	}

	qmode, err := parseQueueMode(*queueModeStr)
	if err != nil {
		log.Error("invalid -ch-queue-mode", "err", err)
		os.Exit(1)
	}

	sink, err := newClickhouseSink(log, *chDSN, *eventsTable, *peersTable, *batchSize, *flushInt, *queueSize, qmode)
	if err != nil {
		log.Error("clickhouse", "err", err)
		os.Exit(1)
	}
	defer sink.Close()

	allow := parseAllowlist(*allowlistFlag)
	if len(allow) > 0 {
		log.Info("bmpgrapes router allowlist active", "routers", *allowlistFlag)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(ctx, "tcp", *listenAddr)
	if err != nil {
		log.Error("listen", "addr", *listenAddr, "err", err)
		os.Exit(1)
	}
	defer ln.Close()
	log.Info("bmpgrapes listening", "addr", *listenAddr,
		"ch_events_table", *eventsTable,
		"ch_peers_table", *peersTable,
	)

	var (
		sessionsOpen     atomic.Int64
		sessionsAccepted atomic.Uint64
		sessionsClosed   atomic.Uint64
		messagesParsed   atomic.Uint64
		messagesRejected atomic.Uint64
		bgpParseErrs     atomic.Uint64
	)

	tick := time.NewTicker(*metricsInterval)
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
				log.Info("bmpgrapes server",
					"sessions_open", sessionsOpen.Load(),
					"sessions_accepted", sessionsAccepted.Load(),
					"sessions_closed", sessionsClosed.Load(),
					"messages_parsed", messagesParsed.Load(),
					"messages_rejected", messagesRejected.Load(),
					"bgp_parse_errs", bgpParseErrs.Load(),
				)
			}
		}
	}()

	// Accept loop: spawn one goroutine per BMP session.
	var sessionsWG sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if ctx.Err() != nil {
					return
				}
				log.Warn("bmpgrapes accept", "err", err)
				continue
			}
			remote := conn.RemoteAddr().(*net.TCPAddr)
			if len(allow) > 0 && !allow[remote.IP.String()] {
				log.Warn("bmpgrapes reject (not in allowlist)", "remote", remote.IP.String())
				_ = conn.Close()
				messagesRejected.Add(1)
				continue
			}
			sessionsAccepted.Add(1)
			sessionsOpen.Add(1)
			sessionsWG.Add(1)
			go func(c net.Conn) {
				defer sessionsWG.Done()
				defer func() {
					_ = c.Close()
					sessionsOpen.Add(-1)
					sessionsClosed.Add(1)
				}()
				handleSession(ctx, log, c, sink, *maxMsgSize, *updateSampleN, &messagesParsed, &bgpParseErrs)
			}(conn)
		}
	}()

	<-ctx.Done()
	log.Info("bmpgrapes shutting down")
	_ = ln.Close()
	sessionsWG.Wait()
	tick.Stop()
	metricsWG.Wait()
}

func newLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.ToLower(strings.TrimSpace(format)) == "json" {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h)
}

func bmpTypeName(t uint8) string {
	switch t {
	case bmpMsgRouteMonitoring:
		return "route_monitoring"
	case bmpMsgStatisticsReport:
		return "statistics_report"
	case bmpMsgPeerDownNotif:
		return "peer_down"
	case bmpMsgPeerUpNotif:
		return "peer_up"
	case bmpMsgInitiation:
		return "initiation"
	case bmpMsgTermination:
		return "termination"
	case bmpMsgRouteMirroring:
		return "route_mirroring"
	default:
		return "unknown"
	}
}

func hexHead(b []byte, n int) string {
	if n > len(b) {
		n = len(b)
	}
	return hex.EncodeToString(b[:n])
}

func prefixString(r RouteEventRow) string {
	if r.Family == 4 {
		ip := net.IPv4(r.Prefix[0], r.Prefix[1], r.Prefix[2], r.Prefix[3])
		return ip.String() + "/" + strconv.Itoa(int(r.PrefixLen))
	}
	return net.IP(r.Prefix[:]).String() + "/" + strconv.Itoa(int(r.PrefixLen))
}

func nextHopString(r RouteEventRow) string {
	if r.Family == 4 {
		ip := net.IPv4(r.NextHop[0], r.NextHop[1], r.NextHop[2], r.NextHop[3])
		return ip.String()
	}
	return net.IP(r.NextHop[:]).String()
}

func parseAllowlist(s string) map[string]bool {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out[p] = true
		}
	}
	return out
}

// handleSession reads BMP messages from a single router connection until EOF or
// a fatal protocol error.
func handleSession(
	ctx context.Context,
	log *slog.Logger,
	conn net.Conn,
	sink *clickhouseSink,
	maxMsgSize int,
	updateSampleN uint64,
	messagesParsed *atomic.Uint64,
	bgpParseErrs *atomic.Uint64,
) {
	remote := conn.RemoteAddr().(*net.TCPAddr)
	routerIP := remote.IP
	var routerAddr [16]byte
	copy(routerAddr[:], routerIP.To16())
	log = log.With("router", routerIP.String())
	log.Info("bmpgrapes session opened")
	defer log.Info("bmpgrapes session closed")

	var (
		sessionMsgs      atomic.Uint64
		sessionRouteMons atomic.Uint64
		sessionAnnounces atomic.Uint64
		sessionWithdraws atomic.Uint64
		sessionParseErrs atomic.Uint64
		sessionUpdSamples atomic.Uint64
	)

	r := bufio.NewReaderSize(conn, 1<<20)
	for {
		if ctx.Err() != nil {
			return
		}
		h, err := readBMPCommonHeader(r)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Info("bmpgrapes session ended",
					"messages", sessionMsgs.Load(),
					"route_monitoring", sessionRouteMons.Load(),
					"announces", sessionAnnounces.Load(),
					"withdraws", sessionWithdraws.Load(),
					"parse_errs", sessionParseErrs.Load(),
				)
				return
			}
			log.Warn("bmpgrapes header read", "err", err)
			return
		}
		if int(h.Length) > maxMsgSize {
			log.Warn("bmpgrapes message too large", "length", h.Length, "limit", maxMsgSize)
			return
		}
		body, err := readBMPBody(r, h)
		if err != nil {
			log.Warn("bmpgrapes body read", "err", err)
			return
		}
		messagesParsed.Add(1)
		sessionMsgs.Add(1)
		now := time.Now().UTC()

		log.Debug("bmpgrapes bmp message",
			"type", bmpTypeName(h.Type),
			"type_code", h.Type,
			"length", h.Length,
		)

		switch h.Type {
		case bmpMsgInitiation:
			log.Debug("bmpgrapes initiation message", "body_len", len(body))
		case bmpMsgTermination:
			log.Info("bmpgrapes termination message received")
			return
		case bmpMsgPeerUpNotif:
			ph, rest, err := parseBMPPeerHeader(body)
			if err != nil {
				sessionParseErrs.Add(1)
				log.Warn("bmpgrapes peer up header",
					"err", err,
					"body_hex_head", hexHead(body, 64),
				)
				continue
			}
			pu, err := parseBMPPeerUp(rest)
			if err != nil {
				sessionParseErrs.Add(1)
				log.Warn("bmpgrapes peer up body",
					"err", err,
					"body_hex_head", hexHead(rest, 64),
				)
				continue
			}
			row := peerRowFromUp(now, routerAddr, ph, pu)
			sink.EnqueuePeers(ctx, []PeerRow{row})
			log.Info("bmpgrapes peer up",
				"peer", peerAddressNetIP(ph.PeerAddress, ph.IsIPv6()),
				"peer_asn", ph.PeerAS,
				"peer_type", ph.PeerType,
				"is_ipv6", ph.IsIPv6(),
				"local", peerAddressNetIP(pu.LocalAddress, ph.IsIPv6()),
				"local_port", pu.LocalPort,
				"remote_port", pu.RemotePort,
				"bgp_id", ph.PeerBGPID,
			)
		case bmpMsgPeerDownNotif:
			ph, rest, err := parseBMPPeerHeader(body)
			if err != nil {
				sessionParseErrs.Add(1)
				log.Warn("bmpgrapes peer down header",
					"err", err,
					"body_hex_head", hexHead(body, 64),
				)
				continue
			}
			reason := ""
			if len(rest) >= 1 {
				reason = peerDownReason(rest[0])
			}
			row := peerRowFromDown(now, routerAddr, ph, reason)
			sink.EnqueuePeers(ctx, []PeerRow{row})
			log.Info("bmpgrapes peer down",
				"peer", peerAddressNetIP(ph.PeerAddress, ph.IsIPv6()),
				"peer_asn", ph.PeerAS,
				"reason", reason,
			)
		case bmpMsgRouteMonitoring:
			sessionRouteMons.Add(1)
			ph, rest, err := parseBMPPeerHeader(body)
			if err != nil {
				sessionParseErrs.Add(1)
				log.Warn("bmpgrapes route monitoring header",
					"err", err,
					"body_hex_head", hexHead(body, 64),
				)
				continue
			}
			bgpMsg, _, err := peelBGPMessage(rest)
			if err != nil {
				bgpParseErrs.Add(1)
				sessionParseErrs.Add(1)
				log.Warn("bmpgrapes bgp peel",
					"err", err,
					"peer", peerAddressNetIP(ph.PeerAddress, ph.IsIPv6()),
					"peer_asn", ph.PeerAS,
					"body_hex_head", hexHead(rest, 64),
				)
				continue
			}
			upd, err := parseBGPUpdate(bgpMsg)
			if err != nil {
				bgpParseErrs.Add(1)
				sessionParseErrs.Add(1)
				log.Warn("bmpgrapes bgp update parse",
					"err", err,
					"peer", peerAddressNetIP(ph.PeerAddress, ph.IsIPv6()),
					"peer_asn", ph.PeerAS,
					"bgp_hex_head", hexHead(bgpMsg, 64),
				)
				continue
			}
			rows := buildRouteEventRows(now, routerAddr, ph, upd)
			if len(rows) == 0 {
				continue
			}
			var ann, wdr uint64
			for _, r := range rows {
				if r.EventType == "announce" {
					ann++
				} else {
					wdr++
				}
			}
			sessionAnnounces.Add(ann)
			sessionWithdraws.Add(wdr)
			sink.EnqueueEvents(ctx, rows)
			if sessionUpdSamples.Load() < updateSampleN {
				sessionUpdSamples.Add(1)
				first := rows[0]
				log.Info("bmpgrapes bgp update sample",
					"peer", peerAddressNetIP(ph.PeerAddress, ph.IsIPv6()),
					"peer_asn", ph.PeerAS,
					"event", first.EventType,
					"family", first.Family,
					"prefix", prefixString(first),
					"next_hop", nextHopString(first),
					"origin_asn", first.OriginASN,
					"as_path_len", len(first.ASPath),
					"announces_in_msg", ann,
					"withdraws_in_msg", wdr,
				)
			}
		case bmpMsgStatisticsReport:
			log.Debug("bmpgrapes statistics report", "body_len", len(body))
		case bmpMsgRouteMirroring:
			log.Debug("bmpgrapes route mirroring", "body_len", len(body))
		default:
			log.Debug("bmpgrapes unknown bmp type", "type_code", h.Type, "length", h.Length)
		}
	}
}

func peerRowFromUp(ts time.Time, router [16]byte, ph bmpPeerHeader, pu bmpPeerUpInfo) PeerRow {
	row := PeerRow{
		Ts:         ts,
		RouterAddr: router,
		PeerAddr:   ph.PeerAddress,
		PeerASN:    ph.PeerAS,
		PeerType:   ph.PeerType,
		IsIPv6:     boolToUint8(ph.IsIPv6()),
		State:      "up",
		LocalAddr:  pu.LocalAddress,
		BGPID:      ph.PeerBGPID,
	}
	return row
}

func peerRowFromDown(ts time.Time, router [16]byte, ph bmpPeerHeader, reason string) PeerRow {
	return PeerRow{
		Ts:         ts,
		RouterAddr: router,
		PeerAddr:   ph.PeerAddress,
		PeerASN:    ph.PeerAS,
		PeerType:   ph.PeerType,
		IsIPv6:     boolToUint8(ph.IsIPv6()),
		State:      "down",
		Reason:     reason,
		BGPID:      ph.PeerBGPID,
	}
}

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func peerDownReason(code byte) string {
	switch code {
	case 1:
		return "local_system_close_notification"
	case 2:
		return "local_system_close_fsm"
	case 3:
		return "remote_system_close_notification"
	case 4:
		return "remote_system_close_no_notification"
	case 5:
		return "peer_de-configured"
	default:
		return "unknown"
	}
}

func buildRouteEventRows(ts time.Time, router [16]byte, ph bmpPeerHeader, upd bgpUpdate) []RouteEventRow {
	commonOrigin := uint32(0)
	if len(upd.ASPath) > 0 {
		commonOrigin = upd.ASPath[len(upd.ASPath)-1]
	}
	var nextHopV4 [16]byte
	if upd.HaveNextHopV4 {
		// Store IPv4 in the first 4 bytes of the 16-byte slot.
		copy(nextHopV4[:4], upd.NextHopV4[:])
	}
	var nextHopV6 [16]byte
	if upd.HaveNextHopV6 {
		copy(nextHopV6[:], upd.NextHopV6[:])
	}
	out := make([]RouteEventRow, 0, len(upd.WithdrawnV4)+len(upd.AnnouncedV4)+len(upd.WithdrawnV6)+len(upd.AnnouncedV6))
	for _, w := range upd.WithdrawnV4 {
		out = append(out, RouteEventRow{
			Ts: ts, RouterAddr: router,
			PeerAddr: ph.PeerAddress, PeerASN: ph.PeerAS,
			EventType: "withdraw", Family: 4,
			Prefix: w.Prefix, PrefixLen: w.PrefixLen,
		})
	}
	for _, a := range upd.AnnouncedV4 {
		out = append(out, RouteEventRow{
			Ts: ts, RouterAddr: router,
			PeerAddr: ph.PeerAddress, PeerASN: ph.PeerAS,
			EventType: "announce", Family: 4,
			Prefix: a.Prefix, PrefixLen: a.PrefixLen,
			NextHop: nextHopV4,
			OriginASN: commonOrigin,
			ASPath: upd.ASPath,
			MED: upd.MED, LocalPref: upd.LocalPref,
		})
	}
	for _, w := range upd.WithdrawnV6 {
		out = append(out, RouteEventRow{
			Ts: ts, RouterAddr: router,
			PeerAddr: ph.PeerAddress, PeerASN: ph.PeerAS,
			EventType: "withdraw", Family: 6,
			Prefix: w.Prefix, PrefixLen: w.PrefixLen,
		})
	}
	for _, a := range upd.AnnouncedV6 {
		out = append(out, RouteEventRow{
			Ts: ts, RouterAddr: router,
			PeerAddr: ph.PeerAddress, PeerASN: ph.PeerAS,
			EventType: "announce", Family: 6,
			Prefix: a.Prefix, PrefixLen: a.PrefixLen,
			NextHop: nextHopV6,
			OriginASN: commonOrigin,
			ASPath: upd.ASPath,
			MED: upd.MED, LocalPref: upd.LocalPref,
		})
	}
	return out
}
