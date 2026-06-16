package main

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"xdpflowd/internal/flowingest"
)

type sflowListener struct {
	log        *slog.Logger
	addr       string
	sourceID   string
	readBuf    int
	readers    int
	workers    int
	queueSize  int
	batchSize  int
	flushEvery time.Duration
	delivery   *flowingest.Delivery
	classifier *flowingest.TrafficClassifier
	seq        atomic.Uint32
	metrics    sflowMetrics
}

func newSflowListener(
	log *slog.Logger,
	addr, sourceID string,
	readBuf int,
	readers int,
	workers int,
	queueSize int,
	batchSize int,
	flushEvery time.Duration,
	delivery *flowingest.Delivery,
	classifier *flowingest.TrafficClassifier,
) *sflowListener {
	if batchSize < 1 {
		batchSize = 1
	}
	if flushEvery <= 0 {
		flushEvery = time.Second
	}
	if readers < 1 {
		readers = 1
	}
	if workers < 1 {
		workers = 1
	}
	if queueSize < 1 {
		queueSize = 1
	}
	return &sflowListener{
		log:        log,
		addr:       addr,
		sourceID:   sourceID,
		readBuf:    readBuf,
		readers:    readers,
		workers:    workers,
		queueSize:  queueSize,
		batchSize:  batchSize,
		flushEvery: flushEvery,
		delivery:   delivery,
		classifier: classifier,
	}
}

type sflowDatagram struct {
	b          []byte
	receivedAt time.Time
}

// maxUDPDatagramSize bounds the per-read userspace buffer. A single UDP
// datagram never exceeds 65535 bytes, so the read buffer is fixed regardless
// of the (much larger) kernel SO_RCVBUF set via FC_UDP_READ_BUFFER.
const maxUDPDatagramSize = 65535

func (l *sflowListener) Run(ctx context.Context) error {
	datagramBufSize := maxUDPDatagramSize

	readers := make([]*net.UDPConn, 0, l.readers)
	for i := 0; i < l.readers; i++ {
		pc, err := listenUDPReusePort(ctx, l.addr)
		if err != nil {
			for _, r := range readers {
				_ = r.Close()
			}
			return err
		}
		if l.readBuf > 0 {
			if err := pc.SetReadBuffer(l.readBuf); err != nil {
				l.log.Warn("sflow set udp read buffer", "reader", i, "requested_bytes", l.readBuf, "err", err)
			}
		}
		readers = append(readers, pc)
	}

	l.log.Info("sflow listener started",
		"addr", l.addr,
		"source_id", l.sourceID,
		"udp_read_buffer_bytes", l.readBuf,
		"datagram_buffer_bytes", datagramBufSize,
		"udp_readers", l.readers,
		"udp_workers", l.workers,
		"udp_queue_size", l.queueSize,
	)

	datagrams := make(chan sflowDatagram, l.queueSize)
	var workerWG sync.WaitGroup
	for i := 0; i < l.workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			l.runWorker(ctx, datagrams)
		}()
	}

	errCh := make(chan error, 1)
	var readerWG sync.WaitGroup
	for i, pc := range readers {
		readerWG.Add(1)
		go func(id int, conn *net.UDPConn) {
			defer readerWG.Done()
			if err := l.runReader(ctx, id, conn, datagramBufSize, datagrams); err != nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}(i, pc)
	}
	defer func() {
		for _, r := range readers {
			_ = r.Close()
		}
		readerWG.Wait()
		close(datagrams)
		workerWG.Wait()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func listenUDPReusePort(ctx context.Context, addr string) (*net.UDPConn, error) {
	var lc net.ListenConfig
	lc.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
				sockErr = err
				return
			}
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
				sockErr = err
				return
			}
		}); err != nil {
			return err
		}
		return sockErr
	}
	pc, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, net.InvalidAddrError("expected UDPConn")
	}
	return udpConn, nil
}

func (l *sflowListener) runReader(ctx context.Context, id int, pc *net.UDPConn, datagramBufSize int, datagrams chan<- sflowDatagram) error {
	buf := make([]byte, datagramBufSize)
	for {
		if ctx.Err() != nil {
			return nil
		}
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := pc.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			l.log.Warn("sflow read", "reader", id, "err", err)
			return err
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])
		d := sflowDatagram{b: cp, receivedAt: time.Now().UTC()}
		select {
		case datagrams <- d:
		default:
			l.metrics.udpQueueDrops.Add(1)
		}
	}
}

func (l *sflowListener) runWorker(ctx context.Context, datagrams <-chan sflowDatagram) {
	pending := make([]flowingest.FlowRow, 0, l.batchSize)
	nextFlush := time.Now().Add(l.flushEvery)
	flush := func() {
		if len(pending) == 0 || l.delivery == nil {
			pending = pending[:0]
			nextFlush = time.Now().Add(l.flushEvery)
			return
		}
		l.delivery.EnqueueRows(pending)
		pending = make([]flowingest.FlowRow, 0, l.batchSize)
		nextFlush = time.Now().Add(l.flushEvery)
	}
	ticker := time.NewTicker(l.flushEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-ticker.C:
			if time.Now().After(nextFlush) || time.Now().Equal(nextFlush) {
				flush()
			}
		case d, ok := <-datagrams:
			if !ok {
				flush()
				return
			}
			rows := parseSFlowV5(d.b, d.receivedAt, l.sourceID, l.classifier, nil, &l.metrics)
			for i := range rows {
				rows[i].SequenceNum = l.seq.Add(1)
			}
			if len(rows) > 0 {
				pending = append(pending, rows...)
				if len(pending) >= l.batchSize || time.Now().After(nextFlush) || time.Now().Equal(nextFlush) {
					flush()
				}
			}
		}
	}
}

func (l *sflowListener) LogMetrics() {
	if l == nil {
		return
	}
	l.log.Info("sflow",
		"datagrams", l.metrics.datagrams.Load(),
		"flow_samples", l.metrics.flowSamples.Load(),
		"records_parsed", l.metrics.recordsParsed.Load(),
		"counter_skipped", l.metrics.counterSkipped.Load(),
		"parse_errors", l.metrics.parseErrors.Load(),
		"unknown_samples", l.metrics.unknownSamples.Load(),
		"udp_queue_drops", l.metrics.udpQueueDrops.Load(),
	)
}
