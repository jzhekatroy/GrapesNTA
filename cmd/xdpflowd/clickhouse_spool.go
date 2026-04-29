package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const (
	spoolFrameVersion   = uint32(1)
	spoolFrameMagicBE   = uint32(0x50464c58) // 'PFLX' big-endian on wire
	spoolFrameHeaderLen = 24
)

type consumerCheckpoint struct {
	Segment uint64 `json:"segment"`
	Offset  int64  `json:"offset"`
}

func (c consumerCheckpoint) String() string {
	return fmt.Sprintf("seg=%d off=%d", c.Segment, c.Offset)
}

// spoolWriter appends checksum-protected gob-encoded FlowRow batches to segment files.
type spoolWriter struct {
	log           *slog.Logger
	dir           string
	segDir        string
	metaDir       string
	maxSegBytes   int64
	maxTotalBytes int64
	maxFrameRows  int
	fsyncEvery    time.Duration
	requiredMode  bool

	mu        sync.Mutex
	segID     uint64
	file      *os.File
	segBytes  int64
	lastFsync time.Time
	frameSeq  atomic.Uint64

	writerTipSeg atomic.Uint64
	writerTipOff atomic.Int64
}

func openSpoolWriter(log *slog.Logger, dir string, maxSegBytes, maxTotalBytes int64, maxFrameRows int, fsyncEvery time.Duration, required bool) (*spoolWriter, error) {
	if dir == "" {
		return nil, errors.New("spool dir empty")
	}
	if maxFrameRows < 1 {
		maxFrameRows = 50_000
	}
	dir = filepath.Clean(dir)
	segDir := filepath.Join(dir, "segments")
	metaDir := filepath.Join(dir, "meta")
	for _, d := range []string{dir, segDir, metaDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	maxID, err := scanMaxSegmentID(segDir)
	if err != nil {
		return nil, err
	}
	nextID := maxID + 1
	if nextID == 1 {
		// fresh spool
	} else {
		// Continue numbering; old segments remain for consumer replay.
	}
	w := &spoolWriter{
		log:           log,
		dir:           dir,
		segDir:        segDir,
		metaDir:       metaDir,
		maxSegBytes:   maxSegBytes,
		maxTotalBytes: maxTotalBytes,
		maxFrameRows:  maxFrameRows,
		fsyncEvery:    fsyncEvery,
		requiredMode:  required,
		segID:         nextID,
	}
	f, off, err := w.openSegmentFile(nextID)
	if err != nil {
		return nil, err
	}
	w.file = f
	w.segBytes = off
	w.writerTipSeg.Store(nextID)
	w.writerTipOff.Store(off)
	log.Info("clickhouse spool writer open", "dir", dir, "segment", nextID, "resume_offset", off)
	return w, nil
}

func scanMaxSegmentID(segDir string) (uint64, error) {
	ents, err := os.ReadDir(segDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	var ids []uint64
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".seg") {
			continue
		}
		n := strings.TrimSuffix(name, ".seg")
		id, err := strconv.ParseUint(n, 10, 64)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids[len(ids)-1], nil
}

func dirSegBytesSum(segDir string) (int64, error) {
	ents, err := os.ReadDir(segDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	var sum int64
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		sum += fi.Size()
	}
	return sum, nil
}

func (w *spoolWriter) openSegmentFile(id uint64) (*os.File, int64, error) {
	path := filepath.Join(w.segDir, fmt.Sprintf("%016d.seg", id))
	// Append if exists (crash mid-way); consumer offset controls replay.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

func encodeFramePayload(rows []FlowRow) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(&rows); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeFramePayload(b []byte) ([]FlowRow, error) {
	dec := gob.NewDecoder(bytes.NewReader(b))
	var rows []FlowRow
	if err := dec.Decode(&rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func buildFrame(seq uint64, payload []byte) []byte {
	var h [spoolFrameHeaderLen]byte
	binary.BigEndian.PutUint32(h[0:4], spoolFrameMagicBE)
	binary.BigEndian.PutUint32(h[4:8], spoolFrameVersion)
	binary.BigEndian.PutUint64(h[8:16], seq)
	binary.BigEndian.PutUint32(h[16:20], uint32(len(payload)))
	crc := crc32.ChecksumIEEE(payload)
	binary.BigEndian.PutUint32(h[20:24], crc)
	out := make([]byte, 0, spoolFrameHeaderLen+len(payload))
	out = append(out, h[:]...)
	out = append(out, payload...)
	return out
}

func parseFrameHeader(b []byte) (seq uint64, payloadLen uint32, crc uint32, ok bool) {
	if len(b) < spoolFrameHeaderLen {
		return 0, 0, 0, false
	}
	if binary.BigEndian.Uint32(b[0:4]) != spoolFrameMagicBE {
		return 0, 0, 0, false
	}
	if binary.BigEndian.Uint32(b[4:8]) != spoolFrameVersion {
		return 0, 0, 0, false
	}
	seq = binary.BigEndian.Uint64(b[8:16])
	payloadLen = binary.BigEndian.Uint32(b[16:20])
	crc = binary.BigEndian.Uint32(b[20:24])
	return seq, payloadLen, crc, true
}

// AppendBatch writes one or more durable frames. Large scan batches are split so
// ClickHouse workers can replay/ack incrementally under high-cardinality traffic.
func (w *spoolWriter) AppendBatch(rows []FlowRow) (consumerCheckpoint, error) {
	var cp consumerCheckpoint
	if len(rows) == 0 {
		return cp, nil
	}
	chunkSize := w.maxFrameRows
	if chunkSize < 1 {
		chunkSize = 50_000
	}
	for start := 0; start < len(rows); start += chunkSize {
		end := start + chunkSize
		if end > len(rows) {
			end = len(rows)
		}
		next, err := w.appendFrame(rows[start:end])
		if err != nil {
			return cp, err
		}
		cp = next
	}
	return cp, nil
}

func (w *spoolWriter) appendFrame(rows []FlowRow) (consumerCheckpoint, error) {
	var cp consumerCheckpoint
	payload, err := encodeFramePayload(rows)
	if err != nil {
		return cp, err
	}
	seq := w.frameSeq.Add(1)
	frame := buildFrame(seq, payload)

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.maxTotalBytes > 0 {
		cur, err := dirSegBytesSum(w.segDir)
		if err != nil {
			if w.requiredMode {
				return cp, fmt.Errorf("spool size check (required): %w", err)
			}
			w.log.Warn("spool size check", "err", err)
		} else if cur+int64(len(frame)) > w.maxTotalBytes {
			return cp, fmt.Errorf("spool max total bytes exceeded (cur=%d add=%d max=%d)", cur, len(frame), w.maxTotalBytes)
		}
	}

	if w.maxSegBytes > 0 && w.segBytes > 0 && w.segBytes+int64(len(frame)) > w.maxSegBytes {
		if err := w.rotateUnlocked(); err != nil {
			return cp, err
		}
	}

	n, err := w.file.Write(frame)
	if err != nil {
		if w.requiredMode {
			return cp, fmt.Errorf("spool write (required): %w", err)
		}
		return cp, err
	}
	w.segBytes += int64(n)
	endOff := w.segBytes

	shouldFsync := false
	if w.fsyncEvery <= 0 {
		shouldFsync = true
	} else {
		now := time.Now()
		if w.lastFsync.IsZero() || now.Sub(w.lastFsync) >= w.fsyncEvery {
			shouldFsync = true
			w.lastFsync = now
		}
	}
	if shouldFsync {
		if err := w.file.Sync(); err != nil {
			if w.requiredMode {
				return cp, fmt.Errorf("spool fsync (required): %w", err)
			}
			w.log.Warn("spool fsync", "err", err)
		}
	}

	cp = consumerCheckpoint{Segment: w.segID, Offset: endOff}
	w.writerTipSeg.Store(w.segID)
	w.writerTipOff.Store(endOff)
	return cp, nil
}

func (w *spoolWriter) rotateUnlocked() error {
	if w.file != nil {
		_ = w.file.Sync()
		_ = w.file.Close()
		w.file = nil
	}
	w.segID++
	f, off, err := w.openSegmentFile(w.segID)
	if err != nil {
		return err
	}
	w.file = f
	w.segBytes = off
	w.writerTipSeg.Store(w.segID)
	w.writerTipOff.Store(off)
	w.log.Info("clickhouse spool rotated", "segment", w.segID)
	return nil
}

func (w *spoolWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Sync()
	_ = w.file.Close()
	w.file = nil
	return err
}

func consumerPath(dir string) string {
	return filepath.Join(dir, "meta", "consumer.json")
}

func loadCheckpoint(dir string) (consumerCheckpoint, error) {
	var cp consumerCheckpoint
	b, err := os.ReadFile(consumerPath(dir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return consumerCheckpoint{Segment: 1, Offset: 0}, nil
		}
		return cp, err
	}
	if err := json.Unmarshal(b, &cp); err != nil {
		return cp, err
	}
	if cp.Segment == 0 {
		cp.Segment = 1
	}
	return cp, nil
}

func saveCheckpoint(dir string, cp consumerCheckpoint) error {
	tmp := consumerPath(dir) + ".tmp"
	b, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, consumerPath(dir))
}

func cleanupAckedSegments(log *slog.Logger, segDir string, cp consumerCheckpoint) {
	ents, err := os.ReadDir(segDir)
	if err != nil {
		log.Warn("spool cleanup read dir", "err", err)
		return
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".seg") {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(e.Name(), ".seg"), 10, 64)
		if err != nil || id >= cp.Segment {
			continue
		}
		path := filepath.Join(segDir, e.Name())
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Warn("spool cleanup remove segment", "segment", id, "err", err)
		}
	}
}

// readNextFrame reads a single frame at cp; returns new offset after frame, rows, bool ok.
func readNextFrame(segDir string, cp consumerCheckpoint) (next consumerCheckpoint, rows []FlowRow, err error) {
	path := filepath.Join(segDir, fmt.Sprintf("%016d.seg", cp.Segment))
	f, err := os.Open(path)
	if err != nil {
		return cp, nil, err
	}
	defer f.Close()
	if cp.Offset > 0 {
		if _, err := f.Seek(cp.Offset, io.SeekStart); err != nil {
			return cp, nil, err
		}
	}
	hdr := make([]byte, spoolFrameHeaderLen)
	if _, err := io.ReadFull(f, hdr); err != nil {
		if errors.Is(err, io.EOF) {
			return cp, nil, io.EOF
		}
		return cp, nil, err
	}
	seq, payLen, wantCRC, ok := parseFrameHeader(hdr)
	if !ok {
		return cp, nil, fmt.Errorf("bad frame header at %s off=%d", path, cp.Offset)
	}
	if payLen > 256*1024*1024 {
		return cp, nil, fmt.Errorf("excessive payload len %d", payLen)
	}
	payload := make([]byte, payLen)
	if _, err := io.ReadFull(f, payload); err != nil {
		return cp, nil, err
	}
	if crc32.ChecksumIEEE(payload) != wantCRC {
		return cp, nil, fmt.Errorf("crc mismatch at %s seg=%d off=%d seq=%d", path, cp.Segment, cp.Offset, seq)
	}
	rows, err = decodeFramePayload(payload)
	if err != nil {
		return cp, nil, err
	}
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return cp, nil, err
	}
	next = consumerCheckpoint{Segment: cp.Segment, Offset: pos}
	return next, rows, nil
}

// --- Delivery pipeline: spool + parallel ClickHouse writers with ordered acks ---

type spoolClickhousePipeline struct {
	log    *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc

	writer       *spoolWriter
	conn         chdriver.Conn
	table        string
	mode         chSpoolMode
	nWorkers     int
	drainOnClose time.Duration

	checkpointMu sync.Mutex
	// persisted consumer offset (acked prefix)
	acked consumerCheckpoint

	recordsSpooled atomic.Uint64
	recordsAcked   atomic.Uint64
	insertErrs     atomic.Uint64
	retries        atomic.Uint64
	batchesOK      atomic.Uint64

	wg sync.WaitGroup
}

func newSpoolClickhousePipeline(
	log *slog.Logger,
	dsn, table string,
	spoolDir string,
	maxSegBytes int64,
	maxTotalBytes int64,
	maxFrameRows int,
	fsyncEvery time.Duration,
	drainOnClose time.Duration,
	mode chSpoolMode,
	nWorkers int,
) (*spoolClickhousePipeline, error) {
	if nWorkers < 1 {
		nWorkers = 1
	}
	opts, err := parseClickHouseDSN(dsn)
	if err != nil {
		return nil, err
	}
	minConns := nWorkers + 2
	if minConns < 5 {
		minConns = 5
	}
	if opts.MaxOpenConns < minConns {
		opts.MaxOpenConns = minConns
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}
	cp, err := loadCheckpoint(spoolDir)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("spool load checkpoint: %w", err)
	}
	wr, err := openSpoolWriter(log, spoolDir, maxSegBytes, maxTotalBytes, maxFrameRows, fsyncEvery, mode == chSpoolRequired)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &spoolClickhousePipeline{
		log:          log,
		ctx:          ctx,
		cancel:       cancel,
		writer:       wr,
		conn:         conn,
		table:        table,
		mode:         mode,
		nWorkers:     nWorkers,
		drainOnClose: drainOnClose,
		acked:        cp,
	}
	p.wg.Add(1)
	go p.runPipeline()
	log.Info("clickhouse spool pipeline started",
		"dir", spoolDir,
		"checkpoint", cp,
		"writers", nWorkers,
		"mode", mode.String(),
		"frame_max_records", maxFrameRows,
		"shutdown_drain", drainOnClose,
	)
	return p, nil
}

type chSpoolMode int

func (m chSpoolMode) String() string {
	switch m {
	case chSpoolOff:
		return "off"
	case chSpoolOn:
		return "on"
	case chSpoolRequired:
		return "required"
	default:
		return "unknown"
	}
}

const (
	chSpoolOff chSpoolMode = iota
	chSpoolOn
	chSpoolRequired
)

type spoolJob struct {
	seq  uint64
	rows []FlowRow
	ack  consumerCheckpoint
}

// runPipeline owns worker pool, acknowledger, and spool drainer lifecycle.
func (p *spoolClickhousePipeline) runPipeline() {
	defer p.wg.Done()

	cp, err := loadCheckpoint(p.writer.dir)
	if err != nil {
		p.log.Error("spool load checkpoint", "err", err)
		return
	}
	p.checkpointMu.Lock()
	p.acked = cp
	p.checkpointMu.Unlock()

	jobs := make(chan spoolJob, p.nWorkers*32)
	completions := make(chan spoolCompletion, p.nWorkers*32)

	var workerWG sync.WaitGroup
	for i := 0; i < p.nWorkers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for job := range jobs {
				ok := p.insertWithRetry(job.rows)
				if ok {
					p.recordsAcked.Add(uint64(len(job.rows)))
					p.batchesOK.Add(1)
				}
				completions <- spoolCompletion{seq: job.seq, ack: job.ack, ok: ok}
			}
		}()
	}

	var ackWG sync.WaitGroup
	ackWG.Add(1)
	go func() {
		defer ackWG.Done()
		p.runAcker(completions)
	}()

	go func() {
		workerWG.Wait()
		close(completions)
	}()

	p.drainerLoop(jobs)

	close(jobs)
	workerWG.Wait()
	ackWG.Wait()
}

// drainerLoop reads frames from disk ahead of the durable ack watermark (at-least-once).
func (p *spoolClickhousePipeline) drainerLoop(jobs chan<- spoolJob) {
	readHead, err := loadCheckpoint(p.writer.dir)
	if err != nil {
		p.log.Error("spool drainer load checkpoint", "err", err)
		return
	}
	jobSeq := uint64(0)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	for {
		if p.ctx.Err() != nil {
			// Data is already durable in spool. On shutdown, leave unacked frames
			// for replay instead of blocking process exit on ClickHouse.
			return
		}
		tipSeg := p.writer.writerTipSeg.Load()
		tipOff := p.writer.writerTipOff.Load()

		hasData := readHead.Segment < tipSeg || (readHead.Segment == tipSeg && readHead.Offset < tipOff)

		if !hasData {
			select {
			case <-ticker.C:
			case <-p.ctx.Done():
				// keep looping until caught up after writer closed
			}
			continue
		}

		nextCP, rows, err := readNextFrame(p.writer.segDir, readHead)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if readHead.Segment < tipSeg {
					readHead = consumerCheckpoint{Segment: readHead.Segment + 1, Offset: 0}
					continue
				}
				select {
				case <-ticker.C:
				case <-p.ctx.Done():
				}
				continue
			}
			if errors.Is(err, os.ErrNotExist) {
				readHead.Segment++
				readHead.Offset = 0
				continue
			}
			p.log.Warn("spool read frame", "err", err, "at", readHead)
			select {
			case <-ticker.C:
			case <-p.ctx.Done():
			}
			continue
		}

		j := jobSeq
		jobSeq++
		select {
		case jobs <- spoolJob{seq: j, rows: rows, ack: nextCP}:
			readHead = nextCP
		case <-p.ctx.Done():
			// try non-blocking send to avoid losing this frame if workers still up
			select {
			case jobs <- spoolJob{seq: j, rows: rows, ack: nextCP}:
				readHead = nextCP
			default:
				// If we cannot enqueue, spin until space — shutdown must drain
				jobs <- spoolJob{seq: j, rows: rows, ack: nextCP}
				readHead = nextCP
			}
		}
	}
}

type spoolCompletion struct {
	seq uint64
	ack consumerCheckpoint
	ok  bool
}

func (p *spoolClickhousePipeline) insertWithRetry(rows []FlowRow) bool {
	backoff := 500 * time.Millisecond
	for {
		select {
		case <-p.ctx.Done():
			return false
		default:
		}
		if insertBatchRows(p.ctx, p.log, p.conn, p.table, rows, &p.insertErrs) {
			return true
		}
		p.retries.Add(1)
		select {
		case <-time.After(backoff):
		case <-p.ctx.Done():
			return false
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (p *spoolClickhousePipeline) runAcker(completions <-chan spoolCompletion) {
	next := uint64(0)
	lastCleanupSegment := uint64(0)
	pending := make(map[uint64]consumerCheckpoint)

	for c := range completions {
		if !c.ok {
			p.log.Error("spool ack: batch never succeeded before channel close — data may remain in spool for replay")
			continue
		}
		pending[c.seq] = c.ack
		for {
			ack, ok := pending[next]
			if !ok {
				break
			}
			if err := saveCheckpoint(p.writer.dir, ack); err != nil {
				p.log.Error("spool save checkpoint", "err", err)
			}
			p.checkpointMu.Lock()
			p.acked = ack
			p.checkpointMu.Unlock()
			if ack.Segment > lastCleanupSegment {
				cleanupAckedSegments(p.log, p.writer.segDir, ack)
				lastCleanupSegment = ack.Segment
			}
			delete(pending, next)
			next++
		}
	}
}

// Append enqueues one batch to disk; drainer will pick up asynchronously.
func (p *spoolClickhousePipeline) Append(rows []FlowRow) error {
	cp, err := p.writer.AppendBatch(rows)
	if err != nil {
		return err
	}
	p.recordsSpooled.Add(uint64(len(rows)))
	_ = cp
	return nil
}

func (p *spoolClickhousePipeline) Close() {
	// Finalize writer tip first so drainer can converge on shutdown.
	if err := p.writer.Close(); err != nil {
		p.log.Warn("spool writer close", "err", err)
	}
	if p.drainOnClose > 0 {
		deadline := time.Now().Add(p.drainOnClose)
		ticker := time.NewTicker(200 * time.Millisecond)
		for {
			if p.isCaughtUp() {
				p.log.Info("clickhouse spool shutdown drain complete",
					"records_spooled", p.recordsSpooled.Load(),
					"records_acked", p.recordsAcked.Load(),
				)
				ticker.Stop()
				break
			}
			if time.Now().After(deadline) {
				p.log.Warn("clickhouse spool shutdown drain timeout",
					"records_spooled", p.recordsSpooled.Load(),
					"records_acked", p.recordsAcked.Load(),
					"timeout", p.drainOnClose,
				)
				ticker.Stop()
				break
			}
			<-ticker.C
		}
	}
	p.cancel()
	p.wg.Wait()
	if p.conn != nil {
		_ = p.conn.Close()
	}
}

func (p *spoolClickhousePipeline) isCaughtUp() bool {
	tipSeg := p.writer.writerTipSeg.Load()
	tipOff := p.writer.writerTipOff.Load()
	p.checkpointMu.Lock()
	cp := p.acked
	p.checkpointMu.Unlock()
	return cp.Segment > tipSeg || (cp.Segment == tipSeg && cp.Offset >= tipOff)
}

func (p *spoolClickhousePipeline) LogMetrics() {
	p.log.Info("clickhouse spool pipeline",
		"records_spooled", p.recordsSpooled.Load(),
		"records_acked", p.recordsAcked.Load(),
		"batches_ok", p.batchesOK.Load(),
		"insert_errs", p.insertErrs.Load(),
		"retries", p.retries.Load(),
	)
}

func parseChSpoolMode(s string) (chSpoolMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "":
		return chSpoolOff, nil
	case "on":
		return chSpoolOn, nil
	case "required":
		return chSpoolRequired, nil
	default:
		return chSpoolOff, fmt.Errorf("unknown -ch-spool-mode %q (off|on|required)", s)
	}
}
