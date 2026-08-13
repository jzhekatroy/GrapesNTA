package netv9

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	version         = 9
	headerLen       = 20
	templateFlowset = 0
	templateIDv4    = 256
	templateIDv6    = 257
	maxUDPPayload   = 1400
)

const (
	fINBytes           = 1
	fINPkts            = 2
	fProtocol          = 4
	fSrcTos            = 5
	fTCPFlags          = 6
	fL4SrcPort         = 7
	fIPV4SrcAddr       = 8
	fInputSNMP         = 10
	fL4DstPort         = 11
	fIPV4DstAddr       = 12
	fLastSwitched      = 21
	fFirstSwitched     = 22
	fIPV6SrcAddr       = 27
	fIPV6DstAddr       = 28
	fMinTTL            = 52
	fMaxTTL            = 53
	fMinPktLngth       = 54
	fMaxPktLngth       = 55
	fSrcVLAN           = 58
	fIPProtocolVersion = 60
)

var fieldsV4 = []struct{ Typ, Length uint16 }{
	{fINBytes, 8}, {fINPkts, 8}, {fProtocol, 1}, {fSrcTos, 1}, {fTCPFlags, 1},
	{fL4SrcPort, 2}, {fIPV4SrcAddr, 4}, {fInputSNMP, 4}, {fL4DstPort, 2}, {fIPV4DstAddr, 4},
	{fFirstSwitched, 4}, {fLastSwitched, 4},
	{fMinTTL, 1}, {fMaxTTL, 1}, {fMinPktLngth, 2}, {fMaxPktLngth, 2},
	{fSrcVLAN, 2}, {fIPProtocolVersion, 1},
}

var fieldsV6 = []struct{ Typ, Length uint16 }{
	{fINBytes, 8}, {fINPkts, 8}, {fProtocol, 1}, {fSrcTos, 1}, {fTCPFlags, 1},
	{fL4SrcPort, 2}, {fIPV6SrcAddr, 16}, {fInputSNMP, 4}, {fL4DstPort, 2}, {fIPV6DstAddr, 16},
	{fFirstSwitched, 4}, {fLastSwitched, 4},
	{fMinTTL, 1}, {fMaxTTL, 1}, {fMinPktLngth, 2}, {fMaxPktLngth, 2},
	{fSrcVLAN, 2}, {fIPProtocolVersion, 1},
}

func recordSize(fields []struct{ Typ, Length uint16 }) int {
	n := 0
	for _, f := range fields {
		n += int(f.Length)
	}
	return n
}

// Exporter sends NetFlow v9 datagrams. Timestamps use CLOCK_MONOTONIC ns since
// process start (same idea as xdpflowd: consistent FIRST/LAST vs sysUptime in header).
type Exporter struct {
	log              *slog.Logger
	dests            []*net.UDPConn
	Dests            []string
	SourceID         uint32
	exporterStart    time.Time
	monoRefNs        uint64 // ClockGettime(CLOCK_MONOTONIC) at NewExporter
	ActiveTimeout    time.Duration
	IdleTimeout      time.Duration
	TemplateInterval time.Duration

	recV4Size int
	recV6Size int
	tmplBytes []byte

	seq              atomic.Uint32
	lastTemplateSent atomic.Int64

	recordsOut atomic.Uint64
	packetsOut atomic.Uint64
	bytesOut   atomic.Uint64
	sendErrs   atomic.Uint64
}

// ReadSystemUptimeNs reads the first field of /proc/uptime in nanoseconds
// (same helper as xdpflowd; optional cross-check with monotonic).
func readSystemUptimeNs() (uint64, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, errors.New("empty /proc/uptime")
	}
	secs, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, err
	}
	return uint64(secs * 1e9), nil
}

func monoNowNs() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec), nil
}

// NewExporter dials all UDP destinations and builds template flowset bytes.
func NewExporter(log *slog.Logger, dests []string, sourceID uint32,
	active, idle, tmplInterval time.Duration,
) (*Exporter, error) {
	if len(dests) == 0 {
		return nil, errors.New("netv9: at least one destination required")
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	mono0, err := monoNowNs()
	if err != nil {
		return nil, fmt.Errorf("netv9: CLOCK_MONOTONIC: %w", err)
	}
	e := &Exporter{
		log:              log,
		SourceID:         sourceID,
		exporterStart:    time.Now(),
		monoRefNs:        mono0,
		ActiveTimeout:    active,
		IdleTimeout:      idle,
		TemplateInterval: tmplInterval,
		Dests:            append([]string{}, dests...),
	}
	for _, d := range dests {
		addr, err := net.ResolveUDPAddr("udp", d)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", d, err)
		}
		c, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			return nil, fmt.Errorf("dial %q: %w", d, err)
		}
		e.dests = append(e.dests, c)
	}
	e.recV4Size = recordSize(fieldsV4)
	e.recV6Size = recordSize(fieldsV6)
	e.tmplBytes = buildTemplateFlowset()
	return e, nil
}

func buildTemplateFlowset() []byte {
	tmpl := func(id uint16, fs []struct{ Typ, Length uint16 }) []byte {
		var buf []byte
		buf = binary.BigEndian.AppendUint16(buf, id)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(fs)))
		for _, f := range fs {
			buf = binary.BigEndian.AppendUint16(buf, f.Typ)
			buf = binary.BigEndian.AppendUint16(buf, f.Length)
		}
		return buf
	}
	t4 := tmpl(templateIDv4, fieldsV4)
	t6 := tmpl(templateIDv6, fieldsV6)
	body := append(t4, t6...)
	length := uint16(4 + len(body))
	if length%4 != 0 {
		pad := 4 - (length % 4)
		body = append(body, make([]byte, pad)...)
		length += pad
	}
	var out []byte
	out = binary.BigEndian.AppendUint16(out, templateFlowset)
	out = binary.BigEndian.AppendUint16(out, length)
	out = append(out, body...)
	return out
}

func (e *Exporter) writeHeader(buf []byte, count uint16) []byte {
	sys := uint32(time.Since(e.exporterStart).Milliseconds())
	now := time.Now().Unix()
	seq := e.seq.Add(1)
	buf = binary.BigEndian.AppendUint16(buf, version)
	buf = binary.BigEndian.AppendUint16(buf, count)
	buf = binary.BigEndian.AppendUint32(buf, sys)
	buf = binary.BigEndian.AppendUint32(buf, uint32(now))
	buf = binary.BigEndian.AppendUint32(buf, seq)
	buf = binary.BigEndian.AppendUint32(buf, e.SourceID)
	return buf
}

// ToSwitchedMs maps monotonic flow timestamps to ms since exporter start (xdpflowd-compatible).
func (e *Exporter) ToSwitchedMs(monoNs uint64) uint32 {
	if monoNs <= e.monoRefNs {
		return 0
	}
	return uint32((monoNs - e.monoRefNs) / 1_000_000)
}

func wirePortBytes(p uint16) (byte, byte) { return byte(p), byte(p >> 8) }

func (e *Exporter) appendRecordV4(buf []byte, k FlowKey, v FlowValue) []byte {
	sp0, sp1 := wirePortBytes(k.SrcPort)
	dp0, dp1 := wirePortBytes(k.DstPort)
	buf = binary.BigEndian.AppendUint64(buf, v.Bytes)
	buf = binary.BigEndian.AppendUint64(buf, v.Packets)
	buf = append(buf, k.Proto, v.Tos, v.TCPFlagsOR, sp0, sp1)
	buf = append(buf, k.SrcAddr[0], k.SrcAddr[1], k.SrcAddr[2], k.SrcAddr[3])
	buf = binary.BigEndian.AppendUint32(buf, v.IngressIf)
	buf = append(buf, dp0, dp1)
	buf = append(buf, k.DstAddr[0], k.DstAddr[1], k.DstAddr[2], k.DstAddr[3])
	buf = binary.BigEndian.AppendUint32(buf, e.ToSwitchedMs(v.FirstSeenNs))
	buf = binary.BigEndian.AppendUint32(buf, e.ToSwitchedMs(v.LastSeenNs))
	buf = append(buf, v.TTLMin, v.TTLMax)
	buf = binary.BigEndian.AppendUint16(buf, v.PktLenMin)
	buf = binary.BigEndian.AppendUint16(buf, v.PktLenMax)
	buf = binary.BigEndian.AppendUint16(buf, k.VLANID)
	buf = append(buf, 4)
	return buf
}

func (e *Exporter) appendRecordV6(buf []byte, k FlowKey, v FlowValue) []byte {
	sp0, sp1 := wirePortBytes(k.SrcPort)
	dp0, dp1 := wirePortBytes(k.DstPort)
	buf = binary.BigEndian.AppendUint64(buf, v.Bytes)
	buf = binary.BigEndian.AppendUint64(buf, v.Packets)
	buf = append(buf, k.Proto, v.Tos, v.TCPFlagsOR, sp0, sp1)
	buf = append(buf, k.SrcAddr[:]...)
	buf = binary.BigEndian.AppendUint32(buf, v.IngressIf)
	buf = append(buf, dp0, dp1)
	buf = append(buf, k.DstAddr[:]...)
	buf = binary.BigEndian.AppendUint32(buf, e.ToSwitchedMs(v.FirstSeenNs))
	buf = binary.BigEndian.AppendUint32(buf, e.ToSwitchedMs(v.LastSeenNs))
	buf = append(buf, v.TTLMin, v.TTLMax)
	buf = binary.BigEndian.AppendUint16(buf, v.PktLenMin)
	buf = binary.BigEndian.AppendUint16(buf, v.PktLenMax)
	buf = binary.BigEndian.AppendUint16(buf, k.VLANID)
	buf = append(buf, 6)
	return buf
}

func (e *Exporter) send(pkt []byte) {
	for _, c := range e.dests {
		if _, err := c.Write(pkt); err != nil {
			e.sendErrs.Add(1)
			e.log.Warn("netflow send", "err", err, "dst", c.RemoteAddr())
			continue
		}
		e.packetsOut.Add(1)
		e.bytesOut.Add(uint64(len(pkt)))
	}
}

// SendTemplate re-sends both IPv4+IPv6 templates in one flowset.
func (e *Exporter) SendTemplate() {
	buf := make([]byte, 0, headerLen+len(e.tmplBytes))
	buf = e.writeHeader(buf, 2)
	buf = append(buf, e.tmplBytes...)
	e.send(buf)
	e.lastTemplateSent.Store(time.Now().UnixNano())
}

func (e *Exporter) flushBuckets(v4, v6 [][]byte) {
	flush := func(records [][]byte, tmplID uint16, recSize int) {
		if len(records) == 0 {
			return
		}
		perDatagram := (maxUDPPayload - headerLen - 4) / recSize
		if perDatagram < 1 {
			perDatagram = 1
		}
		for i := 0; i < len(records); i += perDatagram {
			end := i + perDatagram
			if end > len(records) {
				end = len(records)
			}
			chunk := records[i:end]
			dataLen := 4 + recSize*len(chunk)
			if dataLen%4 != 0 {
				dataLen += 4 - (dataLen % 4)
			}
			pkt := make([]byte, 0, headerLen+dataLen)
			pkt = e.writeHeader(pkt, uint16(len(chunk)))
			pkt = binary.BigEndian.AppendUint16(pkt, tmplID)
			pkt = binary.BigEndian.AppendUint16(pkt, uint16(dataLen))
			for _, r := range chunk {
				pkt = append(pkt, r...)
			}
			for len(pkt) < headerLen+dataLen {
				pkt = append(pkt, 0)
			}
			e.send(pkt)
			e.recordsOut.Add(uint64(len(chunk)))
		}
	}
	flush(v4, templateIDv4, e.recV4Size)
	flush(v6, templateIDv6, e.recV6Size)
}

// MaybeResendTemplate sends template if interval elapsed (or first call with last=0 after SendTemplate).
func (e *Exporter) MaybeResendTemplate() {
	last := e.lastTemplateSent.Load()
	if last == 0 || time.Since(time.Unix(0, last)) >= e.TemplateInterval {
		e.SendTemplate()
	}
}

// ExportFlows encodes and sends data records; re-sends template if interval elapsed.
// Caller removes keys from the flow store.
func (e *Exporter) ExportFlows(keys []FlowKey, vals []FlowValue) {
	if len(keys) == 0 || len(keys) != len(vals) {
		return
	}
	recV4, recV6 := e.encodeRecords(keys, vals)
	e.MaybeResendTemplate()
	e.flushBuckets(recV4, recV6)
}

// ExportFlowsAfterTemplate is used on shutdown: template was just sent, only data.
func (e *Exporter) ExportFlowsAfterTemplate(keys []FlowKey, vals []FlowValue) {
	if len(keys) == 0 || len(keys) != len(vals) {
		return
	}
	recV4, recV6 := e.encodeRecords(keys, vals)
	e.flushBuckets(recV4, recV6)
}

func (e *Exporter) encodeRecords(keys []FlowKey, vals []FlowValue) (recV4, recV6 [][]byte) {
	for i := range keys {
		k, v := keys[i], vals[i]
		if k.IPVersion == 4 {
			rec := e.appendRecordV4(make([]byte, 0, e.recV4Size), k, v)
			recV4 = append(recV4, rec)
		} else if k.IPVersion == 6 {
			rec := e.appendRecordV6(make([]byte, 0, e.recV6Size), k, v)
			recV6 = append(recV6, rec)
		}
	}
	return recV4, recV6
}

// LogMetrics logs cumulative exporter counters (same fields as xdpflowd).
func (e *Exporter) LogMetrics() {
	e.log.Info("netflow",
		"records", e.recordsOut.Load(),
		"packets_out", e.packetsOut.Load(),
		"bytes_out", e.bytesOut.Load(),
		"send_errs", e.sendErrs.Load(),
		"dsts", strings.Join(e.Dests, ","),
	)
}

// Close closes UDP sockets.
func (e *Exporter) Close() {
	for _, c := range e.dests {
		_ = c.Close()
	}
}

// MonoNow is exported for the dataplane: same clock as ToSwitchedMs.
func MonoNow() (uint64, error) { return monoNowNs() }

// UptimeNS wraps readSystemUptimeNs for tests / idle math aligned with xdpflowd.
func UptimeNS() (uint64, error) { return readSystemUptimeNs() }
