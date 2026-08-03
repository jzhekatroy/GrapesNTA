// netflow.go — NetFlow v9 exporter for xdpflowd.
//
// RFC 3954. We emit two templates:
//   - Template ID 256 (IPv4)
//   - Template ID 257 (IPv6)
//
// Lifecycle: every scan_interval we walk the BPF flow map, pick flows whose
// last_seen or first_seen crossed thresholds (idle/active timeout), copy the
// counters, and delete the map entry. Next packet re-creates a fresh flow —
// so counter drift across export boundaries is bounded by one BPF atomic
// increment, which is acceptable for aggregation purposes.
//
// Packet sizing: we cap each UDP datagram at 1400 B to survive any link MTU
// larger than ~1428 B. Single flowset per packet (simpler parsers accept that).
//
// sysUptime & *_SWITCHED timestamps are expressed relative to our exporter
// process start time. bpf_ktime_get_ns is CLOCK_MONOTONIC (ns since system
// boot); we read the same via /proc/uptime at start to translate.
package main

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
	"xdpflowd/internal/flowingest"
	"xdpflowd/internal/loader"
)

const (
	nfVersion         = 9
	nfHeaderLen       = 20
	nfTemplateFlowset = 0
	nfTemplateIDv4    = 256
	nfTemplateIDv6    = 257
	maxUDPPayload     = 1400
)

// NetFlow v9 field type IDs (IANA IPFIX subset).
const (
	fIN_BYTES            = 1
	fIN_PKTS             = 2
	fPROTOCOL            = 4
	fSRC_TOS             = 5
	fTCP_FLAGS           = 6
	fL4_SRC_PORT         = 7
	fIPV4_SRC_ADDR       = 8
	fINPUT_SNMP          = 10
	fL4_DST_PORT         = 11
	fIPV4_DST_ADDR       = 12
	fIPV4_NEXT_HOP       = 15
	fLAST_SWITCHED       = 21
	fFIRST_SWITCHED      = 22
	fIPV6_SRC_ADDR       = 27
	fIPV6_DST_ADDR       = 28
	fMIN_TTL             = 52
	fMAX_TTL             = 53
	fMIN_PKT_LNGTH       = 54
	fMAX_PKT_LNGTH       = 55
	fIN_SRC_MAC          = 56
	fOUT_DST_MAC         = 57
	fSRC_VLAN            = 58
	fDST_VLAN            = 59
	fIP_PROTOCOL_VERSION = 60
	fIN_DST_MAC          = 80
	fOUT_SRC_MAC         = 81
)

// Field list for IPv4 template (order = wire order of data record).
var fieldsV4 = []struct {
	typ, length uint16
}{
	{fIN_BYTES, 8},
	{fIN_PKTS, 8},
	{fPROTOCOL, 1},
	{fSRC_TOS, 1},
	{fTCP_FLAGS, 1},
	{fL4_SRC_PORT, 2},
	{fIPV4_SRC_ADDR, 4},
	{fINPUT_SNMP, 4},
	{fL4_DST_PORT, 2},
	{fIPV4_DST_ADDR, 4},
	{fFIRST_SWITCHED, 4},
	{fLAST_SWITCHED, 4},
	{fMIN_TTL, 1},
	{fMAX_TTL, 1},
	{fMIN_PKT_LNGTH, 2},
	{fMAX_PKT_LNGTH, 2},
	{fIPV4_NEXT_HOP, 4},
	{fIN_SRC_MAC, 6},
	{fOUT_DST_MAC, 6},
	{fSRC_VLAN, 2},
	{fDST_VLAN, 2},
	{fIP_PROTOCOL_VERSION, 1},
	{fIN_DST_MAC, 6},
	{fOUT_SRC_MAC, 6},
}

var fieldsV6 = []struct {
	typ, length uint16
}{
	{fIN_BYTES, 8},
	{fIN_PKTS, 8},
	{fPROTOCOL, 1},
	{fSRC_TOS, 1},
	{fTCP_FLAGS, 1},
	{fL4_SRC_PORT, 2},
	{fIPV6_SRC_ADDR, 16},
	{fINPUT_SNMP, 4},
	{fL4_DST_PORT, 2},
	{fIPV6_DST_ADDR, 16},
	{fFIRST_SWITCHED, 4},
	{fLAST_SWITCHED, 4},
	{fMIN_TTL, 1},
	{fMAX_TTL, 1},
	{fMIN_PKT_LNGTH, 2},
	{fMAX_PKT_LNGTH, 2},
	{fIN_SRC_MAC, 6},
	{fOUT_DST_MAC, 6},
	{fSRC_VLAN, 2},
	{fDST_VLAN, 2},
	{fIP_PROTOCOL_VERSION, 1},
	{fIN_DST_MAC, 6},
	{fOUT_SRC_MAC, 6},
}

func recordSize(fields []struct{ typ, length uint16 }) int {
	n := 0
	for _, f := range fields {
		n += int(f.length)
	}
	return n
}

// nfExporter sends NetFlow v9 datagrams to one or more destinations.
type nfExporter struct {
	log              *slog.Logger
	dests            []*net.UDPConn
	destStrs         []string
	sourceID         uint32
	exporterStart    time.Time // wall/mono reference for sysUptime
	bpfStartNs       uint64    // bpf_ktime_get_ns value at exporter start
	activeTimeout    time.Duration
	idleTimeout      time.Duration
	templateInterval time.Duration
	scanInterval     time.Duration
	seq              atomic.Uint32
	lastTemplateSent atomic.Int64 // unix nanoseconds

	recV4Size int
	recV6Size int
	tmplBytes []byte // cached template flowset (contains both v4 and v6)

	// metrics
	recordsOut uint64
	packetsOut uint64
	bytesOut   uint64
	sendErrs   uint64
}

// readSystemUptimeNs returns a monotonic-ish nanosecond timestamp that shares
// a time domain with bpf_ktime_get_ns() (CLOCK_MONOTONIC since system boot).
// Prefers unix.ClockGettime — it resolves through the vDSO on Linux, so the
// call cost is a few nanoseconds and triggers no syscall, no allocations and
// no /proc I/O. Falls back to /proc/uptime if the syscall is unavailable.
func readSystemUptimeNs() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err == nil {
		return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec), nil
	}
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

func newNFExporter(log *slog.Logger, dests []string, sourceID uint32,
	active, idle, tmplInterval, scanInterval time.Duration,
) (*nfExporter, error) {
	if len(dests) == 0 {
		return nil, errors.New("at least one destination required")
	}
	e := &nfExporter{
		log:              log,
		sourceID:         sourceID,
		exporterStart:    time.Now(),
		activeTimeout:    active,
		idleTimeout:      idle,
		templateInterval: tmplInterval,
		scanInterval:     scanInterval,
	}
	bpf0, err := readSystemUptimeNs()
	if err != nil {
		return nil, fmt.Errorf("read /proc/uptime: %w", err)
	}
	e.bpfStartNs = bpf0

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
		e.destStrs = append(e.destStrs, d)
	}

	e.recV4Size = recordSize(fieldsV4)
	e.recV6Size = recordSize(fieldsV6)
	e.tmplBytes = buildTemplateFlowset()
	return e, nil
}

// buildTemplateFlowset returns the bytes of a single Template FlowSet carrying
// both IPv4 and IPv6 templates. Format per RFC 3954 §5.2:
//
//	flowset_id=0 (u16) | length (u16) | template_id=256 (u16) | field_count (u16)
//	| [field_type (u16) | field_length (u16)]*  | (repeat for template_id=257) | padding to 4B
func buildTemplateFlowset() []byte {
	tmpl := func(id uint16, fs []struct{ typ, length uint16 }) []byte {
		buf := make([]byte, 0, 4+4*len(fs))
		buf = binary.BigEndian.AppendUint16(buf, id)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(fs)))
		for _, f := range fs {
			buf = binary.BigEndian.AppendUint16(buf, f.typ)
			buf = binary.BigEndian.AppendUint16(buf, f.length)
		}
		return buf
	}
	t4 := tmpl(nfTemplateIDv4, fieldsV4)
	t6 := tmpl(nfTemplateIDv6, fieldsV6)

	body := append(t4, t6...)
	length := uint16(4 + len(body))
	// align up to 4 bytes
	if length%4 != 0 {
		pad := 4 - (length % 4)
		body = append(body, make([]byte, pad)...)
		length += pad
	}
	out := make([]byte, 0, 4+len(body))
	out = binary.BigEndian.AppendUint16(out, nfTemplateFlowset)
	out = binary.BigEndian.AppendUint16(out, length)
	out = append(out, body...)
	return out
}

func (e *nfExporter) writeHeader(buf []byte, count uint16) []byte {
	sys := uint32(time.Since(e.exporterStart).Milliseconds())
	now := time.Now().Unix()
	seq := e.seq.Add(1)
	buf = binary.BigEndian.AppendUint16(buf, nfVersion)
	buf = binary.BigEndian.AppendUint16(buf, count)
	buf = binary.BigEndian.AppendUint32(buf, sys)
	buf = binary.BigEndian.AppendUint32(buf, uint32(now))
	buf = binary.BigEndian.AppendUint32(buf, seq)
	buf = binary.BigEndian.AppendUint32(buf, e.sourceID)
	return buf
}

// toSwitchedMs converts a bpf_ktime_get_ns value (monotonic since system boot)
// to "ms since exporter start". If the flow predates the exporter, returns 0.
func (e *nfExporter) toSwitchedMs(bpfNs uint64) uint32 {
	if bpfNs <= e.bpfStartNs {
		return 0
	}
	return uint32((bpfNs - e.bpfStartNs) / 1_000_000)
}

// wirePortBytes returns the two bytes for an L4 port in network byte order.
// Ports in FlowKey.SrcPort/DstPort come from BPF as __be16 and Go reads them
// as native (little-endian on amd64), so the low byte of the uint16 holds the
// network MSB. This helper swaps them back for the wire.
func wirePortBytes(p uint16) (byte, byte) { return byte(p), byte(p >> 8) }

// encodeRecordV4 writes one IPv4 flow record to buf in field order of fieldsV4.
func (e *nfExporter) encodeRecordV4(buf []byte, k FlowKey, v FlowValue) []byte {
	sp0, sp1 := wirePortBytes(k.SrcPort)
	dp0, dp1 := wirePortBytes(k.DstPort)
	buf = binary.BigEndian.AppendUint64(buf, v.Bytes)
	buf = binary.BigEndian.AppendUint64(buf, v.Packets)
	buf = append(buf, k.Proto, v.Tos, v.TCPFlagsOR, sp0, sp1)
	buf = append(buf, k.SrcAddr[0], k.SrcAddr[1], k.SrcAddr[2], k.SrcAddr[3])
	buf = binary.BigEndian.AppendUint32(buf, v.IngressIf)
	buf = append(buf, dp0, dp1)
	buf = append(buf, k.DstAddr[0], k.DstAddr[1], k.DstAddr[2], k.DstAddr[3])
	buf = binary.BigEndian.AppendUint32(buf, e.toSwitchedMs(v.FirstSeenNs))
	buf = binary.BigEndian.AppendUint32(buf, e.toSwitchedMs(v.LastSeenNs))
	buf = append(buf, v.TTLMin, v.TTLMax)
	buf = binary.BigEndian.AppendUint16(buf, v.PktLenMin)
	buf = binary.BigEndian.AppendUint16(buf, v.PktLenMax)
	buf = binary.BigEndian.AppendUint32(buf, 0) // IPv4 next hop unknown on mirror/XDP path.
	buf = append(buf, k.SrcMAC[:]...)
	buf = append(buf, 0, 0, 0, 0, 0, 0) // out dst mac unknown.
	buf = binary.BigEndian.AppendUint16(buf, k.VLANID)
	buf = binary.BigEndian.AppendUint16(buf, 0) // dst vlan unknown.
	buf = append(buf, 4)
	buf = append(buf, k.DstMAC[:]...)
	buf = append(buf, 0, 0, 0, 0, 0, 0) // out src mac unknown.
	return buf
}

// encodeRecordV6 is the IPv6 equivalent.
func (e *nfExporter) encodeRecordV6(buf []byte, k FlowKey, v FlowValue) []byte {
	sp0, sp1 := wirePortBytes(k.SrcPort)
	dp0, dp1 := wirePortBytes(k.DstPort)
	buf = binary.BigEndian.AppendUint64(buf, v.Bytes)
	buf = binary.BigEndian.AppendUint64(buf, v.Packets)
	buf = append(buf, k.Proto, v.Tos, v.TCPFlagsOR, sp0, sp1)
	buf = append(buf, k.SrcAddr[:]...)
	buf = binary.BigEndian.AppendUint32(buf, v.IngressIf)
	buf = append(buf, dp0, dp1)
	buf = append(buf, k.DstAddr[:]...)
	buf = binary.BigEndian.AppendUint32(buf, e.toSwitchedMs(v.FirstSeenNs))
	buf = binary.BigEndian.AppendUint32(buf, e.toSwitchedMs(v.LastSeenNs))
	buf = append(buf, v.TTLMin, v.TTLMax)
	buf = binary.BigEndian.AppendUint16(buf, v.PktLenMin)
	buf = binary.BigEndian.AppendUint16(buf, v.PktLenMax)
	buf = append(buf, k.SrcMAC[:]...)
	buf = append(buf, 0, 0, 0, 0, 0, 0) // out dst mac unknown.
	buf = binary.BigEndian.AppendUint16(buf, k.VLANID)
	buf = binary.BigEndian.AppendUint16(buf, 0) // dst vlan unknown.
	buf = append(buf, 6)
	buf = append(buf, k.DstMAC[:]...)
	buf = append(buf, 0, 0, 0, 0, 0, 0) // out src mac unknown.
	return buf
}

// send writes the datagram to all destinations; records metrics.
func (e *nfExporter) send(pkt []byte) {
	for _, c := range e.dests {
		if _, err := c.Write(pkt); err != nil {
			atomic.AddUint64(&e.sendErrs, 1)
			e.log.Warn("netflow send", "err", err, "dst", c.RemoteAddr())
			continue
		}
		atomic.AddUint64(&e.packetsOut, 1)
		atomic.AddUint64(&e.bytesOut, uint64(len(pkt)))
	}
}

// sendTemplate emits a template-only packet (no data). Called at start and
// every templateInterval.
func (e *nfExporter) sendTemplate() {
	buf := make([]byte, 0, nfHeaderLen+len(e.tmplBytes))
	buf = e.writeHeader(buf, 2) // count = number of flowsets = 2 templates
	buf = append(buf, e.tmplBytes...)
	e.send(buf)
	e.lastTemplateSent.Store(time.Now().UnixNano())
}

// flushBuckets ships out collected v4/v6 records in one or more datagrams.
// Each datagram: header + one data flowset (flowset_id=256 or 257).
func (e *nfExporter) flushBuckets(v4 [][]byte, v6 [][]byte) {
	flush := func(records [][]byte, tmplID uint16, recSize int) {
		if len(records) == 0 {
			return
		}
		// chunk records so each UDP datagram fits within maxUDPPayload
		perDatagram := (maxUDPPayload - nfHeaderLen - 4) / recSize
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
				dataLen += 4 - (dataLen % 4) // padding within flowset
			}
			pkt := make([]byte, 0, nfHeaderLen+dataLen)
			// NFv9 header "count" is total records across all flowsets in
			// this packet; we pack one data flowset per datagram, so count
			// equals the number of data records.
			pkt = e.writeHeader(pkt, uint16(len(chunk)))
			pkt = binary.BigEndian.AppendUint16(pkt, tmplID)
			pkt = binary.BigEndian.AppendUint16(pkt, uint16(dataLen))
			for _, r := range chunk {
				pkt = append(pkt, r...)
			}
			// flowset padding
			for len(pkt) < nfHeaderLen+dataLen {
				pkt = append(pkt, 0)
			}
			e.send(pkt)
			atomic.AddUint64(&e.recordsOut, uint64(len(chunk)))
		}
	}
	flush(v4, nfTemplateIDv4, e.recV4Size)
	flush(v6, nfTemplateIDv6, e.recV6Size)
}

// scanAndExport walks the BPF flows map and exports any flow whose activity
// crosses an idle/active boundary. Returns counts of flows exported and deleted.
// If onFlows is non-nil it receives the same slice of flows before UDP encode
// (for optional ClickHouse direct ingest). receivedAt is wall UTC for the export batch.
//
// When drainer is non-nil and its atomic mode is active, the BPF map entries
// are removed in the same LookupAndDelete that captures their final counters
// — so counters added by XDP between iteration and delete are NOT lost. On
// legacy kernels the function follows the classic snapshot+delete contract.
func (e *nfExporter) scanAndExport(objs *loader.Objects, drainer *FlowDrainer, onFlows func([]flowKV, time.Time), agg *flowAggregator) (exported, deleted int) {
	nowMonoNs, _ := readSystemUptimeNs() // cheap, a few hundred ns

	if drainer != nil && drainer.BatchEnabled() {
		receivedAt := time.Now().UTC()
		if last := e.lastTemplateSent.Load(); last == 0 || time.Since(time.Unix(0, last)) >= e.templateInterval {
			e.sendTemplate()
		}
		n, err := drainer.StreamFullBatchDrain(objs, func(chunk []flowKV) error {
			// With aggregation, fold the slice into the cache and emit only
			// completed flows below. Without it, export each slice directly
			// (legacy batch behaviour).
			if agg != nil {
				agg.Merge(chunk)
				return nil
			}
			if onFlows != nil {
				onFlows(chunk, receivedAt)
			}
			e.exportFlowChunk(chunk)
			return nil
		})
		if err != nil && e.log != nil {
			e.log.Error("batch full-drain", "err", err, "drained", n)
		}
		if agg != nil {
			if ready := agg.Collect(nowMonoNs); len(ready) > 0 {
				if onFlows != nil {
					onFlows(ready, receivedAt)
				}
				e.exportFlowChunk(ready)
			}
		}
		return n, n
	}

	// Send template if interval elapsed (or very first run).
	last := e.lastTemplateSent.Load()
	if last == 0 || time.Since(time.Unix(0, last)) >= e.templateInterval {
		e.sendTemplate()
	}

	receivedAt := time.Now().UTC()
	if drainer != nil {
		var err error
		exported, deleted, _, err = drainer.StreamExpired(objs, e.idleTimeout, e.activeTimeout, nowMonoNs, func(chunk []flowKV) error {
			if onFlows != nil {
				onFlows(chunk, receivedAt)
			}
			e.exportFlowChunk(chunk)
			return nil
		})
		if err != nil && e.log != nil {
			e.log.Error("timer drain", "err", err, "exported", exported, "deleted", deleted)
		}
		return
	}

	flows := selectExpiredFlows(objs, e.idleTimeout, e.activeTimeout, nowMonoNs)
	if onFlows != nil {
		onFlows(flows, receivedAt)
	}
	e.exportFlowChunk(flows)
	deleted = deleteFlowKeys(objs, flows)
	exported = len(flows)
	return
}

func (e *nfExporter) exportFlowChunk(flows []flowKV) {
	var recV4, recV6 [][]byte
	for _, fv := range flows {
		if fv.k.IPVersion == 4 {
			rec := e.encodeRecordV4(make([]byte, 0, e.recV4Size), fv.k, fv.v)
			recV4 = append(recV4, rec)
		} else if fv.k.IPVersion == 6 {
			rec := e.encodeRecordV6(make([]byte, 0, e.recV6Size), fv.k, fv.v)
			recV6 = append(recV6, rec)
		}
	}
	e.flushBuckets(recV4, recV6)
}

// flushAll exports every flow currently in the map regardless of timeout.
// Intended for graceful shutdown and for test harnesses to ensure nothing
// is left behind.
func (e *nfExporter) flushAll(objs *loader.Objects, drainer *FlowDrainer, onFlows func([]flowKV, time.Time), agg *flowAggregator) (exported, deleted int) {
	if drainer != nil && drainer.BatchEnabled() {
		receivedAt := time.Now().UTC()
		e.sendTemplate()
		n, err := drainer.StreamFullBatchDrain(objs, func(chunk []flowKV) error {
			if agg != nil {
				agg.Merge(chunk)
				return nil
			}
			if onFlows != nil {
				onFlows(chunk, receivedAt)
			}
			e.exportFlowChunk(chunk)
			return nil
		})
		if err != nil && e.log != nil {
			e.log.Error("final batch full-drain", "err", err, "drained", n)
		}
		// Shutdown: nothing should be left behind, so drain the whole cache
		// regardless of idle/active timeouts.
		if agg != nil {
			if ready := agg.DrainAll(); len(ready) > 0 {
				if onFlows != nil {
					onFlows(ready, receivedAt)
				}
				e.exportFlowChunk(ready)
			}
		}
		return n, n
	}

	// Always send a fresh template right before a forced flush so the collector
	// can decode records even if it just started.
	e.sendTemplate()

	receivedAt := time.Now().UTC()
	if drainer != nil {
		var err error
		exported, deleted, _, err = drainer.StreamAll(objs, func(chunk []flowKV) error {
			if onFlows != nil {
				onFlows(chunk, receivedAt)
			}
			e.exportFlowChunk(chunk)
			return nil
		})
		if err != nil && e.log != nil {
			e.log.Error("final timer drain", "err", err, "exported", exported, "deleted", deleted)
		}
		return
	}

	flows := selectAllFlows(objs)
	if onFlows != nil {
		onFlows(flows, receivedAt)
	}
	e.exportFlowChunk(flows)
	deleted = deleteFlowKeys(objs, flows)
	exported = len(flows)
	return
}

func (e *nfExporter) logMetrics() {
	e.log.Info("netflow",
		"records", atomic.LoadUint64(&e.recordsOut),
		"packets_out", atomic.LoadUint64(&e.packetsOut),
		"bytes_out", atomic.LoadUint64(&e.bytesOut),
		"send_errs", atomic.LoadUint64(&e.sendErrs),
		"dsts", strings.Join(e.destStrs, ","),
	)
}

func (e *nfExporter) sendErrors() uint64 {
	if e == nil {
		return 0
	}
	return atomic.LoadUint64(&e.sendErrs)
}

// metrics reports the export leg for the health snapshot. UDP acknowledges
// nothing, so these counters are the last point the collector can vouch for.
func (e *nfExporter) metrics() flowingest.NetFlowMetrics {
	if e == nil {
		return flowingest.NetFlowMetrics{}
	}
	return flowingest.NetFlowMetrics{
		RecordsOut: atomic.LoadUint64(&e.recordsOut),
		PacketsOut: atomic.LoadUint64(&e.packetsOut),
		BytesOut:   atomic.LoadUint64(&e.bytesOut),
		SendErrs:   atomic.LoadUint64(&e.sendErrs),
		Dsts:       strings.Join(e.destStrs, ","),
	}
}

func (e *nfExporter) destinations() []string {
	if e == nil {
		return nil
	}
	return append([]string(nil), e.destStrs...)
}

func (e *nfExporter) Close() {
	for _, c := range e.dests {
		_ = c.Close()
	}
}

// exportClock exposes monotonic→wall mapping shared with other exporters (e.g. ClickHouse).
func (e *nfExporter) exportClock() ExportClock {
	return ExportClock{
		ExporterStart: e.exporterStart,
		BpfStartNs:    e.bpfStartNs,
	}
}
