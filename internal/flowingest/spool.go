package flowingest

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
	// spoolFrameVersionGob is the legacy gob-encoded payload. Still decoded on
	// read so segments written before the binary-codec rollout drain cleanly.
	spoolFrameVersionGob = uint32(1)
	// spoolFrameVersionBinary is the hand-rolled binary codec without MAC
	// fields. No longer written, still decoded so frames written before the MAC
	// rollout drain cleanly during a rolling restart.
	spoolFrameVersionBinary = uint32(2)
	// spoolFrameVersionBinaryMAC is the binary codec with SrcMAC/DstMAC appended
	// per row. No longer written; still decoded so frames written before the
	// sFlow-metadata rollout drain cleanly during a rolling restart.
	spoolFrameVersionBinaryMAC = uint32(3)
	// spoolFrameVersionBinaryMeta is the current writer format: the MAC-bearing
	// binary codec with InIf/OutIf/TCPFlags/IPTTL/IPTos appended after the MAC
	// pair (see spool_codec.go).
	spoolFrameVersionBinaryMeta = uint32(4)
	spoolFrameMagicBE           = uint32(0x50464c58) // 'PFLX' big-endian on wire
	spoolFrameHeaderLen         = 24
)

// spoolFrameVersionSupported reports whether v is a payload version this build
// can decode. Kept in one place so the reader and the resync scanner agree.
func spoolFrameVersionSupported(v uint32) bool {
	return v == spoolFrameVersionGob ||
		v == spoolFrameVersionBinary ||
		v == spoolFrameVersionBinaryMAC ||
		v == spoolFrameVersionBinaryMeta
}

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

func buildFrame(seq uint64, version uint32, payload []byte) []byte {
	var h [spoolFrameHeaderLen]byte
	binary.BigEndian.PutUint32(h[0:4], spoolFrameMagicBE)
	binary.BigEndian.PutUint32(h[4:8], version)
	binary.BigEndian.PutUint64(h[8:16], seq)
	binary.BigEndian.PutUint32(h[16:20], uint32(len(payload)))
	crc := crc32.ChecksumIEEE(payload)
	binary.BigEndian.PutUint32(h[20:24], crc)
	out := make([]byte, 0, spoolFrameHeaderLen+len(payload))
	out = append(out, h[:]...)
	out = append(out, payload...)
	return out
}

func parseFrameHeader(b []byte) (seq uint64, version uint32, payloadLen uint32, crc uint32, ok bool) {
	if len(b) < spoolFrameHeaderLen {
		return 0, 0, 0, 0, false
	}
	if binary.BigEndian.Uint32(b[0:4]) != spoolFrameMagicBE {
		return 0, 0, 0, 0, false
	}
	version = binary.BigEndian.Uint32(b[4:8])
	if !spoolFrameVersionSupported(version) {
		return 0, 0, 0, 0, false
	}
	seq = binary.BigEndian.Uint64(b[8:16])
	payloadLen = binary.BigEndian.Uint32(b[16:20])
	crc = binary.BigEndian.Uint32(b[20:24])
	return seq, version, payloadLen, crc, true
}

// decodeFramePayloadVersioned dispatches payload decoding by frame version so a
// spool that contains both legacy gob frames and new binary frames (during a
// rolling restart) drains without interruption.
func decodeFramePayloadVersioned(version uint32, b []byte) ([]FlowRow, error) {
	switch version {
	case spoolFrameVersionGob:
		return decodeFramePayload(b)
	case spoolFrameVersionBinary:
		return decodeFlowRowsBinaryVersion(b, false, false)
	case spoolFrameVersionBinaryMAC:
		return decodeFlowRowsBinaryVersion(b, true, false)
	case spoolFrameVersionBinaryMeta:
		return decodeFlowRowsBinaryVersion(b, true, true)
	default:
		return nil, fmt.Errorf("unsupported spool frame version %d", version)
	}
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
	payload, err := encodeFlowRowsBinary(rows)
	if err != nil {
		return cp, err
	}
	seq := w.frameSeq.Add(1)
	frame := buildFrame(seq, spoolFrameVersionBinaryMeta, payload)

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

// defaultCheckpoint returns the safe initial checkpoint used when no consumer
// state is present or after recovery from a corrupt one.
func defaultCheckpoint() consumerCheckpoint {
	return consumerCheckpoint{Segment: 1, Offset: 0}
}

// loadCheckpoint reads consumer state from disk. When the file is missing it
// returns the default fresh-start checkpoint. When the file is present but
// unparseable (e.g. truncated, hand-edited, partially written) the bad file is
// quarantined as consumer.json.corrupt.<unix_ns> and the default checkpoint is
// returned — preventing a crash-loop where the pipeline cannot even start.
func loadCheckpoint(log *slog.Logger, dir string) (consumerCheckpoint, error) {
	path := consumerPath(dir)
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return defaultCheckpoint(), nil
		}
		return consumerCheckpoint{}, err
	}
	var cp consumerCheckpoint
	if err := json.Unmarshal(b, &cp); err != nil {
		quarantine := fmt.Sprintf("%s.corrupt.%d", path, time.Now().UnixNano())
		if rerr := os.Rename(path, quarantine); rerr != nil {
			if log != nil {
				log.Error("spool checkpoint corrupt; quarantine rename failed; resetting in place",
					"err", err, "rename_err", rerr, "quarantine", quarantine)
			}
		} else if log != nil {
			log.Error("spool checkpoint corrupt; quarantined and reset to defaults",
				"err", err, "quarantine", quarantine)
		}
		return defaultCheckpoint(), nil
	}
	if cp.Segment == 0 {
		cp.Segment = 1
	}
	return cp, nil
}

// scanSegmentRange returns the min/max segment id present on disk and a flag
// indicating whether any segment files were found. Non-numeric or non-.seg
// entries are ignored, matching scanMaxSegmentID semantics.
func scanSegmentRange(segDir string) (minID, maxID uint64, hasSegs bool, err error) {
	ents, err := os.ReadDir(segDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, false, nil
		}
		return 0, 0, false, err
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".seg") {
			continue
		}
		id, perr := strconv.ParseUint(strings.TrimSuffix(name, ".seg"), 10, 64)
		if perr != nil {
			continue
		}
		if !hasSegs || id < minID {
			minID = id
		}
		if !hasSegs || id > maxID {
			maxID = id
		}
		hasSegs = true
	}
	return minID, maxID, hasSegs, nil
}

// normalizeCheckpoint adjusts cp so it falls within the segment range that
// actually exists on disk. Two failure modes are handled:
//
//   - "ahead of writer": cp.Segment > maxID+1 (e.g. left over from a previous
//     spool epoch that was cleaned up). The drainer would otherwise wait
//     forever for segments that will never arrive, while cleanupAckedSegments
//     would delete every real segment on first successful ack. Reset to the
//     oldest segment on disk so we replay all retained data.
//   - "behind retention": cp.Segment < minID (segments aged out). Advance to
//     the oldest segment that still exists.
//
// If no segments exist on disk the checkpoint is left as-is (the writer will
// create segment N=cp.Segment or a fresh one, and the drainer will follow).
//
// Returns the (possibly unchanged) checkpoint and a bool indicating whether a
// correction was applied.
func normalizeCheckpoint(log *slog.Logger, segDir string, cp consumerCheckpoint) (consumerCheckpoint, bool) {
	minID, maxID, hasSegs, err := scanSegmentRange(segDir)
	if err != nil {
		if log != nil {
			log.Warn("spool normalize: scan segments failed; leaving checkpoint as-is", "err", err)
		}
		return cp, false
	}
	if !hasSegs {
		return cp, false
	}
	// upper bound: the writer either appends to maxID or rotates to maxID+1
	// next, so cp.Segment may legitimately equal maxID+1 (offset must be 0
	// there). Anything beyond that is impossible without disk loss.
	upper := maxID + 1
	if cp.Segment > upper {
		fixed := consumerCheckpoint{Segment: minID, Offset: 0}
		if log != nil {
			log.Warn("spool normalize: checkpoint ahead of writer; resetting to oldest segment",
				"old", cp, "new", fixed, "min_seg", minID, "max_seg", maxID)
		}
		return fixed, true
	}
	if cp.Segment < minID {
		fixed := consumerCheckpoint{Segment: minID, Offset: 0}
		if log != nil {
			log.Warn("spool normalize: checkpoint behind retention; advancing to oldest segment",
				"old", cp, "new", fixed, "min_seg", minID, "max_seg", maxID)
		}
		return fixed, true
	}
	return cp, false
}

// loadAndNormalizeCheckpoint combines on-disk recovery, segment-range
// normalization, and a write-back of the corrected value so subsequent
// readers (drainer, acker, restarts) see the sanitized checkpoint.
func loadAndNormalizeCheckpoint(log *slog.Logger, dir string) (consumerCheckpoint, error) {
	cp, err := loadCheckpoint(log, dir)
	if err != nil {
		return cp, err
	}
	fixed, changed := normalizeCheckpoint(log, filepath.Join(dir, "segments"), cp)
	if changed {
		if serr := saveCheckpoint(dir, fixed); serr != nil && log != nil {
			log.Warn("spool normalize: persist corrected checkpoint failed", "err", serr)
		}
	}
	return fixed, nil
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

func cleanupAckedSegments(log *slog.Logger, segDir string, cp consumerCheckpoint, includeCurrent bool) {
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
		if err != nil {
			continue
		}
		path := filepath.Join(segDir, e.Name())
		if id > cp.Segment || (id == cp.Segment && !includeCurrent) {
			continue
		}
		if id == cp.Segment {
			fi, err := e.Info()
			if err != nil {
				log.Warn("spool cleanup stat segment", "segment", id, "err", err)
				continue
			}
			if cp.Offset < fi.Size() {
				continue
			}
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Warn("spool cleanup remove segment", "segment", id, "err", err)
		} else {
			log.Info("spool cleanup removed acked segment", "segment", id)
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
	seq, version, payLen, wantCRC, ok := parseFrameHeader(hdr)
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
	rows, err = decodeFramePayloadVersioned(version, payload)
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

// resyncToNextMagic scans forward from cp.Offset+1 looking for the next valid
// frame header magic in the current segment, capped at the writer's tip to
// avoid racing partial appends. On miss inside a closed/older segment it rolls
// to the next segment. Returns the new checkpoint, bytes skipped relative to
// cp.Offset, whether a magic was found inside the same segment, and any IO
// error. When the corrupt region is in the writer's *current* segment and no
// magic is found yet, the caller must wait for more data and try again.
func resyncToNextMagic(segDir string, cp consumerCheckpoint, tipSeg uint64, tipOff int64) (next consumerCheckpoint, scanned int64, found bool, err error) {
	path := filepath.Join(segDir, fmt.Sprintf("%016d.seg", cp.Segment))
	f, err := os.Open(path)
	if err != nil {
		return cp, 0, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return cp, 0, false, err
	}
	ceiling := fi.Size()
	if cp.Segment == tipSeg && tipOff < ceiling {
		ceiling = tipOff
	}
	startOff := cp.Offset + 1
	if startOff < 0 {
		startOff = 0
	}
	if startOff >= ceiling {
		if cp.Segment < tipSeg {
			return consumerCheckpoint{Segment: cp.Segment + 1, Offset: 0}, fi.Size() - cp.Offset, false, nil
		}
		return cp, 0, false, nil
	}
	if _, err := f.Seek(startOff, io.SeekStart); err != nil {
		return cp, 0, false, err
	}
	const winSize = 64 * 1024
	buf := make([]byte, winSize+3)
	overlap := 0
	pos := startOff
	for pos < ceiling {
		toRead := int64(winSize)
		if pos+toRead > ceiling {
			toRead = ceiling - pos
		}
		if toRead <= 0 {
			break
		}
		n, rerr := f.Read(buf[overlap : overlap+int(toRead)])
		if n <= 0 {
			if rerr != nil && !errors.Is(rerr, io.EOF) {
				return cp, 0, false, rerr
			}
			break
		}
		total := overlap + n
		for i := 0; i+4 <= total; i++ {
			if binary.BigEndian.Uint32(buf[i:i+4]) != spoolFrameMagicBE {
				continue
			}
			// Verify version when we have enough bytes; otherwise accept the
			// magic position and let the next readNextFrame call validate.
			if i+8 <= total && !spoolFrameVersionSupported(binary.BigEndian.Uint32(buf[i+4:i+8])) {
				continue
			}
			fileOff := pos - int64(overlap) + int64(i)
			if fileOff < startOff {
				continue
			}
			return consumerCheckpoint{Segment: cp.Segment, Offset: fileOff}, fileOff - cp.Offset, true, nil
		}
		if total >= 3 {
			copy(buf[0:3], buf[total-3:total])
			overlap = 3
		} else {
			overlap = total
		}
		pos += int64(n)
	}
	if cp.Segment < tipSeg {
		return consumerCheckpoint{Segment: cp.Segment + 1, Offset: 0}, fi.Size() - cp.Offset, false, nil
	}
	return cp, 0, false, nil
}

// --- Delivery pipeline: spool + parallel ClickHouse writers with ordered acks ---

type SpoolPipeline struct {
	log    *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc

	writer       *spoolWriter
	conn         chdriver.Conn
	table        string
	mode         SpoolMode
	nWorkers     int
	drainOnClose time.Duration
	allowedSourceID string

	checkpointMu sync.Mutex
	// persisted consumer offset (acked prefix)
	acked consumerCheckpoint

	recordsSpooled atomic.Uint64
	recordsAcked   atomic.Uint64
	flowPacketsSpooled atomic.Uint64
	flowBytesSpooled   atomic.Uint64
	flowPacketsAcked   atomic.Uint64
	flowBytesAcked     atomic.Uint64
	insertErrs     atomic.Uint64
	retries        atomic.Uint64
	batchesOK      atomic.Uint64
	sourceRowsSkipped atomic.Uint64

	// Drainer corruption-recovery counters and progress probe.
	corruptionFramesSkipped atomic.Uint64
	corruptionBytesSkipped  atomic.Uint64
	lastDrainerProgress     atomic.Int64 // unix nanoseconds; 0 = never

	// stallThreshold triggers forced resync when drainer makes no progress
	// despite having unread spooled data; also bounds shutdown drain wait.
	stallThreshold time.Duration

	wg sync.WaitGroup
}

func NewSpoolPipeline(
	log *slog.Logger,
	dsn, table string,
	spoolDir string,
	maxSegBytes int64,
	maxTotalBytes int64,
	maxFrameRows int,
	fsyncEvery time.Duration,
	drainOnClose time.Duration,
	stallThreshold time.Duration,
	mode SpoolMode,
	nWorkers int,
	allowedSourceID string,
) (*SpoolPipeline, error) {
	if nWorkers < 1 {
		nWorkers = 1
	}
	opts, err := ParseClickHouseDSN(dsn)
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
	wr, err := openSpoolWriter(log, spoolDir, maxSegBytes, maxTotalBytes, maxFrameRows, fsyncEvery, mode == SpoolRequired)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	// Normalize AFTER the writer has scanned/created segments so the
	// reset target reflects real on-disk state. Quarantines a corrupt
	// consumer.json and rewinds checkpoints that point outside the
	// existing segment range (typical after spool cleanup).
	cp, err := loadAndNormalizeCheckpoint(log, spoolDir)
	if err != nil {
		_ = wr.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("spool load checkpoint: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &SpoolPipeline{
		log:            log,
		ctx:            ctx,
		cancel:         cancel,
		writer:         wr,
		conn:           conn,
		table:          table,
		mode:           mode,
		nWorkers:       nWorkers,
		drainOnClose:   drainOnClose,
		allowedSourceID: strings.TrimSpace(allowedSourceID),
		stallThreshold: stallThreshold,
		acked:          cp,
	}
	p.lastDrainerProgress.Store(time.Now().UnixNano())
	p.wg.Add(1)
	go p.runPipeline()
	log.Info("clickhouse spool pipeline started",
		"dir", spoolDir,
		"checkpoint", cp,
		"writers", nWorkers,
		"mode", mode.String(),
		"frame_max_records", maxFrameRows,
		"shutdown_drain", drainOnClose,
		"stall_threshold", stallThreshold,
		"allowed_source_id", p.allowedSourceID,
	)
	return p, nil
}

type SpoolMode int

func (m SpoolMode) String() string {
	switch m {
	case SpoolOff:
		return "off"
	case SpoolOn:
		return "on"
	case SpoolRequired:
		return "required"
	default:
		return "unknown"
	}
}

const (
	SpoolOff SpoolMode = iota
	SpoolOn
	SpoolRequired
)

type spoolJob struct {
	seq  uint64
	rows []FlowRow
	ack  consumerCheckpoint
}

// runPipeline owns worker pool, acknowledger, and spool drainer lifecycle.
func (p *SpoolPipeline) runPipeline() {
	defer p.wg.Done()

	cp, err := loadAndNormalizeCheckpoint(p.log, p.writer.dir)
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
					packets, bytes := SumFlowRows(job.rows)
					p.recordsAcked.Add(uint64(len(job.rows)))
					p.flowPacketsAcked.Add(packets)
					p.flowBytesAcked.Add(bytes)
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
//
// Corruption handling: any error other than EOF / ErrNotExist is treated as a
// suspect frame. The drainer scans forward for the next valid magic (PFLX +
// a supported version), advances the read head past the bad bytes, and continues. This
// keeps a single torn write or stale segment from blocking the entire spool.
// Stall watchdog forces the same resync if no progress is made for
// stallThreshold despite available data.
func (p *SpoolPipeline) drainerLoop(jobs chan<- spoolJob) {
	readHead, err := loadAndNormalizeCheckpoint(p.log, p.writer.dir)
	if err != nil {
		p.log.Error("spool drainer load checkpoint", "err", err)
		return
	}
	jobSeq := uint64(0)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	p.lastDrainerProgress.Store(time.Now().UnixNano())

	// Sticky warn rate-limiter to prevent log storms when a single bad byte
	// is hit ~40 times per second by the 25ms scan ticker.
	var lastWarnAt time.Time
	var suppressed uint64
	warnRateLimited := func(msg string, args ...any) {
		now := time.Now()
		if now.Sub(lastWarnAt) < 5*time.Second {
			suppressed++
			return
		}
		if suppressed > 0 {
			args = append(args, "suppressed_since_last", suppressed)
			suppressed = 0
		}
		p.log.Warn(msg, args...)
		lastWarnAt = now
	}

	tryResync := func(reason string, cause error) (advanced bool) {
		tipSeg := p.writer.writerTipSeg.Load()
		tipOff := p.writer.writerTipOff.Load()
		next, skipped, found, rerr := resyncToNextMagic(p.writer.segDir, readHead, tipSeg, tipOff)
		// Always cool down the watchdog: the writer needs time to extend the
		// segment, and we don't want a 25ms hot loop re-scanning the same range.
		defer p.lastDrainerProgress.Store(time.Now().UnixNano())
		if rerr != nil {
			warnRateLimited("spool resync failed", "err", rerr, "reason", reason, "at", readHead)
			return false
		}
		// Cannot advance: still in writer's tail with no later magic — wait.
		if !found && next.Segment == readHead.Segment && next.Offset == readHead.Offset {
			warnRateLimited("spool stalled at suspect frame; awaiting more data",
				"at", readHead, "reason", reason, "cause", cause)
			return false
		}
		p.corruptionFramesSkipped.Add(1)
		if skipped > 0 {
			p.corruptionBytesSkipped.Add(uint64(skipped))
		}
		p.log.Error("spool corruption skipped",
			"reason", reason,
			"cause", cause,
			"from", readHead,
			"to", next,
			"skipped_bytes", skipped,
			"found_magic_in_segment", found,
		)
		readHead = next
		// Persist the resync point immediately so a process restart does not
		// re-scan the same corrupt bytes.
		if err := saveCheckpoint(p.writer.dir, readHead); err != nil {
			p.log.Warn("spool save checkpoint after resync", "err", err)
		}
		return true
	}

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
			// Idle, not stuck — keep watchdog quiet.
			p.lastDrainerProgress.Store(time.Now().UnixNano())
			select {
			case <-ticker.C:
			case <-p.ctx.Done():
				// keep looping until caught up after writer closed
			}
			continue
		}

		// Stall watchdog: force resync if nothing has advanced for too long.
		if p.stallThreshold > 0 {
			ageNs := time.Now().UnixNano() - p.lastDrainerProgress.Load()
			if time.Duration(ageNs) > p.stallThreshold {
				if !tryResync("stall_watchdog", fmt.Errorf("no drainer progress for %s", time.Duration(ageNs))) {
					select {
					case <-ticker.C:
					case <-p.ctx.Done():
					}
					continue
				}
			}
		}

		nextCP, rows, err := readNextFrame(p.writer.segDir, readHead)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if readHead.Segment < tipSeg {
					readHead = consumerCheckpoint{Segment: readHead.Segment + 1, Offset: 0}
					p.lastDrainerProgress.Store(time.Now().UnixNano())
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
				p.lastDrainerProgress.Store(time.Now().UnixNano())
				continue
			}
			// Any other error (bad header, oversized payload, CRC mismatch,
			// gob decode error) → treat as suspect and scan past it.
			warnRateLimited("spool read frame error", "err", err, "at", readHead)
			if !tryResync("read_frame_error", err) {
				select {
				case <-ticker.C:
				case <-p.ctx.Done():
				}
			}
			continue
		}

		j := jobSeq
		jobSeq++
		select {
		case jobs <- spoolJob{seq: j, rows: rows, ack: nextCP}:
			readHead = nextCP
			p.lastDrainerProgress.Store(time.Now().UnixNano())
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

func (p *SpoolPipeline) insertWithRetry(rows []FlowRow) bool {
	rows = p.filterAllowedSourceRows(rows)
	if len(rows) == 0 {
		return true
	}
	backoff := 500 * time.Millisecond
	for {
		select {
		case <-p.ctx.Done():
			return false
		default:
		}
		if InsertBatchRows(p.ctx, p.log, p.conn, p.table, rows, &p.insertErrs) {
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

func (p *SpoolPipeline) filterAllowedSourceRows(rows []FlowRow) []FlowRow {
	if p.allowedSourceID == "" || len(rows) == 0 {
		return rows
	}
	var out []FlowRow
	skipped := 0
	for i := range rows {
		if rows[i].SourceID == p.allowedSourceID {
			out = append(out, rows[i])
			continue
		}
		skipped++
	}
	if skipped > 0 {
		p.sourceRowsSkipped.Add(uint64(skipped))
		p.log.Warn(
			"clickhouse spool skipped rows with stale source_id",
			"allowed_source_id", p.allowedSourceID,
			"skipped", skipped,
			"frame_rows", len(rows),
		)
	}
	if out == nil {
		return nil
	}
	return out
}

func (p *SpoolPipeline) runAcker(completions <-chan spoolCompletion) {
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
				cleanupAckedSegments(p.log, p.writer.segDir, ack, false)
				lastCleanupSegment = ack.Segment
			}
			delete(pending, next)
			next++
		}
	}
}

// Append enqueues one batch to disk; drainer will pick up asynchronously.
func (p *SpoolPipeline) Append(rows []FlowRow) error {
	cp, err := p.writer.AppendBatch(rows)
	if err != nil {
		return err
	}
	packets, bytes := SumFlowRows(rows)
	p.recordsSpooled.Add(uint64(len(rows)))
	p.flowPacketsSpooled.Add(packets)
	p.flowBytesSpooled.Add(bytes)
	_ = cp
	return nil
}

func (p *SpoolPipeline) Close() {
	// Finalize writer tip first so drainer can converge on shutdown.
	if err := p.writer.Close(); err != nil {
		p.log.Warn("spool writer close", "err", err)
	}
	if p.drainOnClose > 0 {
		// Bound the wait by both an absolute deadline and a no-progress
		// watchdog so a permanently-stuck drainer cannot block systemctl stop.
		deadline := time.Now().Add(p.drainOnClose)
		stallThr := p.stallThreshold
		if stallThr <= 0 || stallThr > p.drainOnClose {
			stallThr = 30 * time.Second
		}
		lastAcked := p.recordsAcked.Load()
		lastChange := time.Now()
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
			cur := p.recordsAcked.Load()
			if cur != lastAcked {
				lastAcked = cur
				lastChange = time.Now()
			} else if time.Since(lastChange) > stallThr {
				p.log.Warn("clickhouse spool shutdown drain aborted (no progress)",
					"records_spooled", p.recordsSpooled.Load(),
					"records_acked", p.recordsAcked.Load(),
					"stall_threshold", stallThr,
					"backlog_for_replay", true,
				)
				ticker.Stop()
				break
			}
			<-ticker.C
		}
	}
	p.cancel()
	p.wg.Wait()
	p.checkpointMu.Lock()
	finalAck := p.acked
	p.checkpointMu.Unlock()
	cleanupAckedSegments(p.log, p.writer.segDir, finalAck, true)
	p.log.Info("clickhouse spool pipeline closed",
		"records_spooled", p.recordsSpooled.Load(),
		"records_acked", p.recordsAcked.Load(),
		"batches_ok", p.batchesOK.Load(),
		"insert_errs", p.insertErrs.Load(),
		"retries", p.retries.Load(),
		"checkpoint", finalAck,
		"writer_tip_segment", p.writer.writerTipSeg.Load(),
		"writer_tip_offset", p.writer.writerTipOff.Load(),
		"caught_up", p.isCaughtUp(),
	)
	if p.conn != nil {
		_ = p.conn.Close()
	}
}

func (p *SpoolPipeline) isCaughtUp() bool {
	tipSeg := p.writer.writerTipSeg.Load()
	tipOff := p.writer.writerTipOff.Load()
	p.checkpointMu.Lock()
	cp := p.acked
	p.checkpointMu.Unlock()
	return cp.Segment > tipSeg || (cp.Segment == tipSeg && cp.Offset >= tipOff)
}

func (p *SpoolPipeline) LogMetrics() {
	s := p.HealthSnapshot()
	p.log.Info("clickhouse spool pipeline",
		"records_spooled", s.RecordsSpooled,
		"records_acked", s.RecordsAcked,
		"batches_ok", p.batchesOK.Load(),
		"insert_errs", s.InsertErrs,
		"retries", p.retries.Load(),
		"source_rows_skipped", p.sourceRowsSkipped.Load(),
		"corruption_frames_skipped", p.corruptionFramesSkipped.Load(),
		"corruption_bytes_skipped", p.corruptionBytesSkipped.Load(),
		"writer_tip", consumerCheckpoint{Segment: p.writer.writerTipSeg.Load(), Offset: p.writer.writerTipOff.Load()},
		"acked", p.currentAckedCheckpoint(),
		"lag_segments", s.LagSegments,
		"drainer_progress_age", s.DrainerProgressAge.Truncate(time.Second),
	)
}

func (p *SpoolPipeline) currentAckedCheckpoint() consumerCheckpoint {
	p.checkpointMu.Lock()
	defer p.checkpointMu.Unlock()
	return p.acked
}

func (p *SpoolPipeline) HealthSnapshot() HealthSnapshot {
	tipSeg := p.writer.writerTipSeg.Load()
	p.checkpointMu.Lock()
	cp := p.acked
	p.checkpointMu.Unlock()
	lagSegs := int64(tipSeg) - int64(cp.Segment)
	if lagSegs < 0 {
		lagSegs = 0
	}
	progressNs := p.lastDrainerProgress.Load()
	progressAge := time.Duration(0)
	if progressNs > 0 {
		progressAge = time.Since(time.Unix(0, progressNs))
	}
	return HealthSnapshot{
		RecordsSpooled:     p.recordsSpooled.Load(),
		RecordsAcked:       p.recordsAcked.Load(),
		FlowPacketsSpooled: p.flowPacketsSpooled.Load(),
		FlowBytesSpooled:   p.flowBytesSpooled.Load(),
		FlowPacketsAcked:   p.flowPacketsAcked.Load(),
		FlowBytesAcked:     p.flowBytesAcked.Load(),
		InsertErrs:         p.insertErrs.Load(),
		LagSegments:        lagSegs,
		DrainerProgressAge: progressAge,
		CorruptionFrames:   p.corruptionFramesSkipped.Load(),
		CorruptionBytes:    p.corruptionBytesSkipped.Load(),
	}
}

func ParseSpoolMode(s string) (SpoolMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "":
		return SpoolOff, nil
	case "on":
		return SpoolOn, nil
	case "required":
		return SpoolRequired, nil
	default:
		return SpoolOff, fmt.Errorf("unknown -ch-spool-mode %q (off|on|required)", s)
	}
}
