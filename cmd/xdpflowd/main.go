// xdpflowd — userspace daemon: load XDP program, attach, read flow map, optional JSON dumps.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"xdpflowd/internal/flowingest"
	"xdpflowd/internal/loader"
)

// FlowKey must match struct flow_key in bpf/xdp_flow.c (packed, 52 bytes).
type FlowKey struct {
	SrcAddr   [16]byte
	DstAddr   [16]byte
	SrcMAC    [6]byte
	DstMAC    [6]byte
	SrcPort   uint16
	DstPort   uint16
	VLANID    uint16
	Proto     uint8
	IPVersion uint8
}

// FlowValue must match struct flow_value in bpf/xdp_flow.c (packed, 64 bytes).
type FlowValue struct {
	Packets     uint64
	Bytes       uint64
	FirstSeenNs uint64
	LastSeenNs  uint64
	IngressIf   uint32
	RxQueue     uint32
	TCPSynCount uint32
	TCPRstCount uint32
	TCPFinCount uint32
	TCPFlagsOR  uint8
	Tos         uint8
	TTLMin      uint8
	TTLMax      uint8
	PktLenMin   uint16
	PktLenMax   uint16
	IPFragCount uint32
}

type jsonSnapshot struct {
	TsUnixNs int64 `json:"ts_unix_ns"`
	Stats    struct {
		TotalPackets uint64 `json:"total_packets"`
		TotalBytes   uint64 `json:"total_bytes"`
		ParseErrors  uint64 `json:"parse_errors"`
		MapFull      uint64 `json:"map_full"`
		NonIPPass    uint64 `json:"non_ip_pass"`
	} `json:"stats"`
	Aggregate struct {
		FlowsInMap     int    `json:"flows_in_map"`
		SumFlowPackets uint64 `json:"sum_flow_packets"`
		SumFlowBytes   uint64 `json:"sum_flow_bytes"`
	} `json:"aggregate"`
	Flows []jsonFlow `json:"flows,omitempty"`
}

type jsonFlow struct {
	Src         string `json:"src"`
	Dst         string `json:"dst"`
	SrcPort     uint16 `json:"src_port_host"`
	DstPort     uint16 `json:"dst_port_host"`
	VLAN        uint16 `json:"vlan_id"`
	Proto       uint8  `json:"proto"`
	IPVersion   uint8  `json:"ip_version"`
	Packets     uint64 `json:"packets"`
	Bytes       uint64 `json:"bytes"`
	IngressIf   uint32 `json:"ingress_ifindex"`
	RxQueue     uint32 `json:"rx_queue"`
	TCPSyn      uint32 `json:"tcp_syn_count"`
	TCPRst      uint32 `json:"tcp_rst_count"`
	TCPFin      uint32 `json:"tcp_fin_count"`
	TCPFlags    string `json:"tcp_flags"`
	Tos         uint8  `json:"tos"`
	TTLMin      uint8  `json:"ttl_min"`
	TTLMax      uint8  `json:"ttl_max"`
	PktLenMin   uint16 `json:"pkt_len_min"`
	PktLenMax   uint16 `json:"pkt_len_max"`
	IPFragCount uint32 `json:"ip_frag_count"`
}

// readStat sums the per-CPU values of stats[idx]. The BPF map is a
// PERCPU_ARRAY, so the kernel keeps one counter per CPU to avoid
// cross-core cache-line contention on the XDP fast path; userspace
// reconstructs the logical total by summing across all CPUs.
func readStat(objs *loader.Objects, idx uint32) uint64 {
	// Pre-sizing the slice to PossibleCPU() avoids any reliance on the
	// library's internal auto-resize behaviour on Lookup.
	perCPU := make([]uint64, ebpf.MustPossibleCPU())
	if err := objs.Stats.Lookup(idx, perCPU); err != nil {
		return 0
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

func zeroStats(objs *loader.Objects) {
	// PERCPU_ARRAY updates must carry exactly PossibleCPU() values —
	// the kernel keeps one slot per *possible* CPU (from
	// /sys/devices/system/cpu/possible), which on hyper-threaded hosts
	// and VMs can differ from runtime.NumCPU().
	nCPU := ebpf.MustPossibleCPU()
	perCPU := make([]uint64, nCPU)
	var k uint32
	for k = 0; k < 16; k++ {
		_ = objs.Stats.Update(k, perCPU, 0)
	}
}

func buildSnapshot(objs *loader.Objects, includeFlows bool) jsonSnapshot {
	var snap jsonSnapshot
	snap.TsUnixNs = time.Now().UnixNano()
	snap.Stats.TotalPackets = readStat(objs, 0)
	snap.Stats.TotalBytes = readStat(objs, 14)
	snap.Stats.ParseErrors = readStat(objs, 1)
	snap.Stats.MapFull = readStat(objs, 2)
	snap.Stats.NonIPPass = readStat(objs, 3)

	var k FlowKey
	var v FlowValue
	iter := objs.Flows.Iterate()
	var sumP, sumB uint64
	n := 0
	for iter.Next(&k, &v) {
		n++
		sumP += v.Packets
		sumB += v.Bytes
		if includeFlows {
			snap.Flows = append(snap.Flows, flowToJSON(k, v))
		}
	}
	snap.Aggregate.FlowsInMap = n
	snap.Aggregate.SumFlowPackets = sumP
	snap.Aggregate.SumFlowBytes = sumB
	return snap
}

func writeJSONLine(path string, snap jsonSnapshot) error {
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// keyPortHost converts a TCP/UDP port stored in network byte order inside a uint16
// field (as read from BPF map memory on little-endian) to host-endian port number.
func keyPortHost(p uint16) uint16 {
	return (p>>8)&0xff | (p<<8)&0xff00
}

func flowToJSON(k FlowKey, v FlowValue) jsonFlow {
	j := jsonFlow{
		Src:         formatIP(k.SrcAddr[:], k.IPVersion),
		Dst:         formatIP(k.DstAddr[:], k.IPVersion),
		SrcPort:     keyPortHost(k.SrcPort),
		DstPort:     keyPortHost(k.DstPort),
		VLAN:        k.VLANID,
		Proto:       k.Proto,
		IPVersion:   k.IPVersion,
		Packets:     v.Packets,
		Bytes:       v.Bytes,
		IngressIf:   v.IngressIf,
		RxQueue:     v.RxQueue,
		TCPSyn:      v.TCPSynCount,
		TCPRst:      v.TCPRstCount,
		TCPFin:      v.TCPFinCount,
		TCPFlags:    tcpFlagsStr(v.TCPFlagsOR),
		Tos:         v.Tos,
		TTLMin:      v.TTLMin,
		TTLMax:      v.TTLMax,
		PktLenMin:   v.PktLenMin,
		PktLenMax:   v.PktLenMax,
		IPFragCount: v.IPFragCount,
	}
	return j
}

func formatIP(addr []byte, ver uint8) string {
	if ver == 4 {
		return net.IPv4(addr[0], addr[1], addr[2], addr[3]).String()
	}
	if ver == 6 {
		return net.IP(addr[:16]).String()
	}
	return "?"
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func tcpFlagsStr(f uint8) string {
	if f == 0 {
		return "-"
	}
	var s string
	if f&0x01 != 0 {
		s += "F"
	}
	if f&0x02 != 0 {
		s += "S"
	}
	if f&0x04 != 0 {
		s += "R"
	}
	if f&0x08 != 0 {
		s += "P"
	}
	if f&0x10 != 0 {
		s += "A"
	}
	if f&0x20 != 0 {
		s += "U"
	}
	return s
}

// logStats prints the cheap PERCPU-array counters with no BPF map iteration.
// Cost is independent of the number of flows in the map — safe to call frequently.
func logStats(log *slog.Logger, objs *loader.Objects) {
	log.Info("stats",
		"total_packets", readStat(objs, 0),
		"total_bytes", readStat(objs, 14),
		"parse_errors", readStat(objs, 1),
		"map_full", readStat(objs, 2),
		"non_ip_pass", readStat(objs, 3),
		"accounted_packets", readStat(objs, 4),
		"l4_parse_fail", readStat(objs, 5),
		"ipv4_fragments", readStat(objs, 6),
		"ipv4_nonfirst_frags", readStat(objs, 7),
		"ipv6_packets", readStat(objs, 8),
		"ipv6_l4_parse_fail", readStat(objs, 9),
		"vlan_tag_seen", readStat(objs, 10),
		"ipv4_packets", readStat(objs, 11),
		"ipv6_fragments", readStat(objs, 12),
		"unsupported_l4", readStat(objs, 13),
	)
}

// topRow is the heap element for dumpTop's bounded top-K selection.
type topRow struct {
	k FlowKey
	v FlowValue
}

// minHeapTopK keeps the K largest flows (by bytes) in O(N·logK) and O(K) memory,
// avoiding the previous behaviour of allocating a slice of every map entry and
// sorting it. Heap invariant: rows[0] is the SMALLEST currently retained, so the
// next candidate is admitted only if it beats the running minimum.
type minHeapTopK struct {
	rows []topRow
	cap  int
}

func newMinHeapTopK(capacity int) *minHeapTopK {
	if capacity < 1 {
		capacity = 1
	}
	return &minHeapTopK{rows: make([]topRow, 0, capacity), cap: capacity}
}

func (h *minHeapTopK) push(k FlowKey, v FlowValue) {
	if len(h.rows) < h.cap {
		h.rows = append(h.rows, topRow{k, v})
		h.siftUp(len(h.rows) - 1)
		return
	}
	if v.Bytes <= h.rows[0].v.Bytes {
		return
	}
	h.rows[0] = topRow{k, v}
	h.siftDown(0)
}

func (h *minHeapTopK) siftUp(i int) {
	for i > 0 {
		p := (i - 1) / 2
		if h.rows[p].v.Bytes <= h.rows[i].v.Bytes {
			break
		}
		h.rows[p], h.rows[i] = h.rows[i], h.rows[p]
		i = p
	}
}

func (h *minHeapTopK) siftDown(i int) {
	n := len(h.rows)
	for {
		l := 2*i + 1
		r := 2*i + 2
		smallest := i
		if l < n && h.rows[l].v.Bytes < h.rows[smallest].v.Bytes {
			smallest = l
		}
		if r < n && h.rows[r].v.Bytes < h.rows[smallest].v.Bytes {
			smallest = r
		}
		if smallest == i {
			break
		}
		h.rows[smallest], h.rows[i] = h.rows[i], h.rows[smallest]
		i = smallest
	}
}

// sortedDesc returns the retained rows sorted by bytes descending.
func (h *minHeapTopK) sortedDesc() []topRow {
	out := h.rows
	sort.Slice(out, func(i, j int) bool { return out[i].v.Bytes > out[j].v.Bytes })
	return out
}

// dumpTop walks the BPF flow map to compute aggregate counters and the top-N
// flows by bytes. Cost is O(flows_in_map); only the K largest are retained so
// peak memory stays at O(topN) rather than O(flows).
func dumpTop(log *slog.Logger, objs *loader.Objects, topN int) {
	if topN <= 0 {
		logStats(log, objs)
		return
	}
	heap := newMinHeapTopK(topN)
	var k FlowKey
	var v FlowValue
	iter := objs.Flows.Iterate()
	flowsInMap := 0
	for iter.Next(&k, &v) {
		flowsInMap++
		heap.push(k, v)
	}
	_ = iter.Err()
	log.Info("stats",
		"flows_in_map", flowsInMap,
		"total_packets", readStat(objs, 0),
		"parse_errors", readStat(objs, 1),
		"map_full", readStat(objs, 2),
		"non_ip_pass", readStat(objs, 3),
		"accounted_packets", readStat(objs, 4),
		"l4_parse_fail", readStat(objs, 5),
		"ipv4_fragments", readStat(objs, 6),
		"ipv4_nonfirst_frags", readStat(objs, 7),
		"ipv6_packets", readStat(objs, 8),
		"ipv6_l4_parse_fail", readStat(objs, 9),
		"vlan_tag_seen", readStat(objs, 10),
		"ipv4_packets", readStat(objs, 11),
		"ipv6_fragments", readStat(objs, 12),
		"unsupported_l4", readStat(objs, 13),
	)
	for _, r := range heap.sortedDesc() {
		sp := keyPortHost(r.k.SrcPort)
		dp := keyPortHost(r.k.DstPort)
		fmt.Printf("  %-6s vlan=%-4d %42s:%-5d -> %-42s:%-5d  pkts=%-8d bytes=%-10d if=%d q=%d syn=%d rst=%d fin=%d ttl=%d-%d plen=%d-%d frags=%d flags=%s\n",
			protoName(r.k.Proto), r.k.VLANID,
			formatIP(r.k.SrcAddr[:], r.k.IPVersion), sp,
			formatIP(r.k.DstAddr[:], r.k.IPVersion), dp,
			r.v.Packets, r.v.Bytes,
			r.v.IngressIf, r.v.RxQueue,
			r.v.TCPSynCount, r.v.TCPRstCount, r.v.TCPFinCount,
			r.v.TTLMin, r.v.TTLMax,
			r.v.PktLenMin, r.v.PktLenMax, r.v.IPFragCount,
			tcpFlagsStr(r.v.TCPFlagsOR),
		)
	}
}

func main() {
	configPath := flag.String("config", "", "optional YAML config file; CLI flags override file values")
	bpfObj := flag.String("bpf", "bpf/xdp_flow.o", "path to compiled BPF ELF (clang -target bpf)")
	iface := flag.String("iface", "ens18", "interface to attach XDP to")
	mode := flag.String("mode", "native", "XDP mode: native|generic")
	topN := flag.Int("top", 15, "show top N flows by bytes (log mode)")
	interval := flag.Duration("interval", 5*time.Second, "stats / JSON dump interval")
	topInterval := flag.Duration("top-interval", 60*time.Second, "interval for the expensive top-N flow dump (full BPF map walk). Cheap PERCPU stats still print on -interval. Set 0 to disable the dump and only print cheap stats.")
	jsonOut := flag.String("json-out", "", "append NDJSON snapshots to this file")
	jsonInterval := flag.Duration("json-interval", 0, "JSON dump interval (defaults to -interval)")
	jsonFlows := flag.Bool("json-include-flows", false, "include per-flow array in JSON (large)")
	once := flag.Bool("once", false, "attach, wait one -interval, write one JSON line if -json-out set, print top once, then exit")
	finalFlushFlows := flag.Bool("final-flush", true, "force-export all remaining flows on graceful shutdown; set false for fast operational restarts (trailing in-map flows are discarded)")

	// NetFlow v9 export flags
	nfDsts := flag.String("nf-dst", "", "NetFlow v9 destinations, comma-separated host:port (e.g. 127.0.0.1:2055,127.0.0.1:9999)")
	nfActive := flag.Duration("nf-active", 120*time.Second, "NetFlow active timeout (export flows older than this)")
	nfIdle := flag.Duration("nf-idle", 15*time.Second, "NetFlow idle timeout (export flows with no packets for this long)")
	nfTemplateInterval := flag.Duration("nf-template-interval", 60*time.Second, "NetFlow template re-send interval")
	nfScan := flag.Duration("nf-scan", 1*time.Second, "how often to walk the flows map for NetFlow export")
	nfSourceID := flag.Int("nf-source-id", 1, "NetFlow v9 source_id field (exporter observation domain)")
	drainMode := flag.String("drain-mode", "timer", "flow drain strategy for the ClickHouse path: timer (idle/active per-key, low row volume) | batch (whole-map BPF_MAP_LOOKUP_AND_DELETE_BATCH each -drain-interval; far faster, prevents map overflow at high pps)")
	drainInterval := flag.Duration("drain-interval", 0, "batch drain period (drain-mode=batch only); 0 = use -nf-active. With -agg-enable this is just the BPF pull cadence (keep small, e.g. 5s); otherwise it is the effective active timeout.")
	aggEnable := flag.Bool("agg-enable", false, "userspace flow aggregation (drain-mode=batch): fold frequent BPF drain slices into one row per flow per active window so ClickHouse/NetFlow get ~1 row per real flow instead of one per drain tick")
	aggIdle := flag.Duration("agg-idle", 15*time.Second, "aggregation idle timeout: emit a cached flow once it has had no new packets for this long")
	aggActive := flag.Duration("agg-active", 60*time.Second, "aggregation active timeout: force-emit a cached flow once it has been alive this long (caps export latency)")
	aggMaxEntries := flag.Int("agg-max-entries", 2_000_000, "max cached flows before the oldest are force-emitted to bound memory (sustained eviction => enable sampling)")
	xdpAction := flag.String("xdp-action", "pass", "XDP return value for accounted IP packets: pass|drop. DROP only on SPAN/mirror interfaces — it stops the kernel stack after accounting and saves CPU.")
	dnsPassthrough := flag.Bool("dns-passthrough", false, "force XDP_PASS for UDP src/dst port 53 even when -xdp-action=drop (SPAN only), so co-located dnsflowd can capture DNS via AF_PACKET; default off")

	heavyExport := flag.Bool("heavy-export", false, "preset for very high flow churn: sets -nf-active=60s -nf-idle=10s -nf-scan=500ms (overrides those flags)")

	chDSN := flag.String("ch-dsn", "", "optional ClickHouse DSN: clickhouse://user:pass@host:9000/database (native protocol)")
	chTable := flag.String("ch-table", "", "MergeTree table for direct INSERT (e.g. default.flows_raw_xdp_direct); see docs/CLICKHOUSE_FLOWS_RAW.md")
	chBatchSize := flag.Int("ch-batch-size", 500, "ClickHouse INSERT batch size")
	chFlushInterval := flag.Duration("ch-flush-interval", time.Second, "ClickHouse flush interval")
	chQueueSize := flag.Int("ch-queue-size", 64, "bounded queue for ClickHouse rows (drops on overflow; direct mode only)")
	chSamplerAddr := flag.String("ch-sampler-addr", "", "IPv4/IPv6 for sampler_address column (empty = all zero bytes)")
	chSpoolModeFlag := flag.String("ch-spool-mode", "off", "durable ClickHouse queue: off|on|required (requires -ch-spool-dir)")
	chSpoolDir := flag.String("ch-spool-dir", "", "directory for durable spool segments (use fast local disk, not the nfdump archive volume)")
	chSpoolSegSize := flag.Int64("ch-spool-segment-size", int64(256*1024*1024), "rotate spool segment files after this many bytes")
	chSpoolMaxBytes := flag.Int64("ch-spool-max-bytes", 0, "reject appends when total spool segments exceed this (0=unlimited)")
	chSpoolFrameMaxRecords := flag.Int("ch-spool-frame-max-records", 50_000, "maximum FlowRow records per durable spool frame / ClickHouse insert")
	chSpoolFsync := flag.Duration("ch-spool-fsync-interval", time.Second, "best-effort fsync interval for spool (0=fsync every append)")
	chSpoolShutdownDrain := flag.Duration("ch-spool-shutdown-drain", 0, "wait up to this duration for spool backlog to reach ClickHouse before shutdown (0=leave backlog for replay)")
	chSpoolStallThreshold := flag.Duration("ch-spool-stall-threshold", 60*time.Second, "force resync past suspect frame if drainer makes no progress for this long while data is available (also bounds shutdown drain when set)")
	chWriters := flag.Int("ch-writers", 4, "parallel ClickHouse INSERT workers when spool mode is on")
	healthInterval := flag.Duration("health-interval", time.Minute, "emit ERROR health log at most this often when flow export/write path is degraded")
	healthSpoolLagSegments := flag.Int64("health-spool-lag-segments", 10, "ERROR when ClickHouse spool lag exceeds this many segments")
	healthWriterLagRows := flag.Uint64("health-writer-lag-rows", 100000, "ERROR when direct ClickHouse queued-written lag exceeds this many rows")
	healthDrainerAge := flag.Duration("health-drainer-age", 2*time.Minute, "ERROR when spool drainer has made no progress for this long while lagging")
	healthLossRatio := flag.Float64("health-loss-ratio", 0.0001, "emit a dedicated ERROR 'xdpflowd flow loss' when dropped/total packets in the health interval exceeds this fraction (0.0001 = 0.01%); set 0 to log on any non-zero loss")
	classifierEnabled := flag.Bool("classifier", false, "enable collector-side traffic classification (L3 roles + L2 VLAN attachment)")
	classifierRefresh := flag.Duration("classifier-refresh", time.Minute, "refresh interval for classifier dictionaries")
	classifierBGPTable := flag.String("classifier-bgp-table", "default.bgp_prefix_origin_current", "ClickHouse source table/view for prefix -> origin ASN")
	classifierIPASNTable := flag.String("classifier-ip-asn-table", "", "optional ClickHouse source table/view for fallback IP prefix -> ASN")
	classifierL3PrefixesView := flag.String("classifier-l3-prefixes-view", "default.net_l3_prefixes_enabled", "ClickHouse view for enabled L3 prefixes")
	classifierL2VLANsView := flag.String("classifier-l2-vlans-view", "default.net_l2_vlans_enabled", "ClickHouse view for enabled L2 VLAN map")
	classifierDirectionSettingsView := flag.String("classifier-direction-settings-view", "default.net_direction_settings_current", "ClickHouse view with the direction mode setting (empty = always derive direction from prefixes)")
	classifierInterfaceRolesView := flag.String("classifier-interface-roles-view", "default.net_interface_roles_effective_current", "ClickHouse view with effective port sides (empty = disabled); the mirror path has no ifIndex, so direction mode ports yields unknown here")
	exclusionsEnabled := flag.Bool("exclusions", true, "drop flows matched by the operator exclusion catalog (applies to both ClickHouse and NetFlow v9 export)")
	exclusionsView := flag.String("exclusions-view", flowingest.DefaultExclusionsTable, "ClickHouse view with enabled flow exclusion rules (empty = disabled)")
	exclusionsRefresh := flag.Duration("exclusions-refresh", time.Minute, "refresh interval for the flow exclusion catalog")
	sourceID := flag.String("source-id", "xdp-default", "logical flow observation point id written to flows_raw.source_id")
	chHealthTable := flag.String("ch-health-table", flowingest.DefaultHealthTable, "ClickHouse table for periodic health snapshots (empty = disabled)")
	collectorID := flag.String("collector-id", "", "collector_id for health snapshots (see net_collectors)")
	phyPktCounters := flag.String("phy-packet-counters", "", "comma-separated ethtool counter names for packets received on the wire, tried in order (empty = built-in list); see `ethtool -S <iface>`")
	phyDiscardCounters := flag.String("phy-discard-counters", "", "comma-separated ethtool counter names for packets the NIC could not accept, tried in order (empty = built-in list)")
	flag.Parse()

	if strings.TrimSpace(*configPath) != "" {
		cfg, err := loadXDPFlowdConfig(strings.TrimSpace(*configPath))
		if err != nil {
			fmt.Fprintf(os.Stderr, "config load: %v\n", err)
			os.Exit(1)
		}
		if err := applyXDPFlowdConfig(flag.CommandLine, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "config apply: %v\n", err)
			os.Exit(1)
		}
	}

	if *heavyExport {
		*nfActive = 60 * time.Second
		*nfIdle = 10 * time.Second
		*nfScan = 500 * time.Millisecond
	}
	if *healthInterval <= 0 {
		*healthInterval = time.Minute
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error("rlimit memlock", "err", err)
		os.Exit(1)
	}

	ifi, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Error("interface lookup", "iface", *iface, "err", err)
		os.Exit(1)
	}

	// XDP_PASS=2, XDP_DROP=1 (values from uapi/linux/bpf.h).
	var xdpFinalAction uint32
	switch strings.ToLower(*xdpAction) {
	case "pass":
		xdpFinalAction = 2
	case "drop":
		xdpFinalAction = 1
	default:
		log.Error("unknown xdp-action", "value", *xdpAction, "allowed", "pass|drop")
		os.Exit(1)
	}

	loaderOpts := loader.Options{XDPFinalAction: xdpFinalAction}
	if *dnsPassthrough {
		loaderOpts.DNSPassthrough = 1
	}
	objs, err := loader.LoadObjectsWithOptions(*bpfObj, loaderOpts)
	if err != nil {
		log.Error("load eBPF objects", "err", err)
		os.Exit(1)
	}
	defer objs.Close()

	zeroStats(objs)

	var xdpFlags link.XDPAttachFlags
	switch *mode {
	case "native":
		xdpFlags = link.XDPDriverMode
	case "generic":
		xdpFlags = link.XDPGenericMode
	default:
		log.Error("unknown mode", "mode", *mode)
		os.Exit(1)
	}

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFlowProg,
		Interface: ifi.Index,
		Flags:     xdpFlags,
	})
	if err != nil {
		log.Error("attach xdp", "err", err)
		os.Exit(1)
	}
	defer lnk.Close()

	log.Info("xdpflowd started", "iface", *iface, "mode", *mode, "ifindex", ifi.Index, "xdp_action", *xdpAction, "dns_passthrough", *dnsPassthrough)
	if *xdpAction == "drop" {
		log.Warn("XDP_DROP mode: accounted IP packets WILL NOT reach the kernel stack — only safe on SPAN/mirror interfaces")
	}

	jInt := *jsonInterval
	if jInt == 0 {
		jInt = *interval
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Choose flow drainer once: atomic LookupAndDelete when supported,
	// snapshot+delete otherwise. Shared by NetFlow and ClickHouse paths so
	// behaviour and metrics are uniform.
	drainer := NewFlowDrainer(log, strings.EqualFold(strings.TrimSpace(*drainMode), "batch"))

	var nfExp *nfExporter
	if *nfDsts != "" {
		dests := splitCSV(*nfDsts)
		var err error
		nfExp, err = newNFExporter(log, dests, uint32(*nfSourceID),
			*nfActive, *nfIdle, *nfTemplateInterval, *nfScan)
		if err != nil {
			log.Error("netflow init", "err", err)
			os.Exit(1)
		}
		defer nfExp.Close()
		log.Info("netflow v9 export enabled",
			"dsts", dests,
			"active_timeout", *nfActive,
			"idle_timeout", *nfIdle,
			"template_interval", *nfTemplateInterval,
			"scan_interval", *nfScan,
			"source_id", *nfSourceID,
		)
		nfExp.sendTemplate()
	}

	var exportClock ExportClock
	needExportClock := nfExp != nil || strings.TrimSpace(*chDSN) != ""
	if needExportClock {
		if nfExp != nil {
			exportClock = nfExp.exportClock()
		} else {
			up, err := readSystemUptimeNs()
			if err != nil {
				log.Error("clickhouse clock /proc/uptime", "err", err)
				os.Exit(1)
			}
			exportClock = ExportClock{
				ExporterStart: time.Now(),
				BpfStartNs:    up,
			}
		}
	}

	spoolMode, err := flowingest.ParseSpoolMode(*chSpoolModeFlag)
	if err != nil {
		log.Error("clickhouse spool", "err", err)
		os.Exit(1)
	}
	if spoolMode != flowingest.SpoolOff {
		if strings.TrimSpace(*chDSN) == "" || strings.TrimSpace(*chTable) == "" {
			log.Error("ch-spool-mode requires both -ch-dsn and -ch-table")
			os.Exit(1)
		}
		if strings.TrimSpace(*chSpoolDir) == "" {
			log.Error("ch-spool-mode requires -ch-spool-dir")
			os.Exit(1)
		}
	}

	var chDel *clickhouseDelivery
	var exclFilter *flowingest.ExclusionFilter
	if strings.TrimSpace(*sourceID) == "" {
		log.Error("source-id must not be empty")
		os.Exit(1)
	}
	*sourceID = strings.TrimSpace(*sourceID)

	if strings.TrimSpace(*chDSN) != "" {
		sampler, err := flowingest.ParseSamplerAddress(*chSamplerAddr)
		if err != nil {
			log.Error("ch-sampler-addr", "err", err)
			os.Exit(1)
		}
		classifier, err := flowingest.NewTrafficClassifier(ctx, log, flowingest.ClassifierConfig{
			Enabled: *classifierEnabled,
			DSN:     strings.TrimSpace(*chDSN),
			Refresh: *classifierRefresh,
			Tables: flowingest.ClassifierTables{
				BGPOrigins:        strings.TrimSpace(*classifierBGPTable),
				IPASNPrefixes:     strings.TrimSpace(*classifierIPASNTable),
				L3Prefixes:        strings.TrimSpace(*classifierL3PrefixesView),
				L2VLANs:           strings.TrimSpace(*classifierL2VLANsView),
				DirectionSettings: strings.TrimSpace(*classifierDirectionSettingsView),
				InterfaceRoles:    strings.TrimSpace(*classifierInterfaceRolesView),
			},
		})
		if err != nil {
			log.Error("traffic classifier init", "err", err)
			os.Exit(1)
		}
		if classifier != nil {
			defer classifier.Close()
		}
		// Installed on the drainer rather than on either sink: excluded flows
		// must disappear from the ClickHouse rows and the NetFlow v9 records
		// alike, and the drainer is the only shared stage of the two paths.
		exclFilter, err = flowingest.NewExclusionFilter(ctx, log, flowingest.ExclusionConfig{
			Enabled: *exclusionsEnabled,
			DSN:     strings.TrimSpace(*chDSN),
			Refresh: *exclusionsRefresh,
			Table:   strings.TrimSpace(*exclusionsView),
		})
		if err != nil {
			log.Error("flow exclusions init", "err", err)
			os.Exit(1)
		}
		if exclFilter != nil {
			defer exclFilter.Close()
			drainer.SetExclusionFilter(newFlowKVExcluder(exclFilter, *sourceID, sampler))
		}
		mapper := newFlowRowMapper(exportClock, sampler, 0, *sourceID, classifier)
		log.Info("flow source configured", "source_id", *sourceID)
		inner, err := flowingest.NewDelivery(log, flowingest.DeliveryConfig{
			DSN:                 strings.TrimSpace(*chDSN),
			Table:               strings.TrimSpace(*chTable),
			BatchSize:           *chBatchSize,
			FlushInterval:       *chFlushInterval,
			QueueSize:           *chQueueSize,
			SpoolMode:           spoolMode,
			SpoolDir:            strings.TrimSpace(*chSpoolDir),
			SpoolSegSize:        *chSpoolSegSize,
			SpoolMaxBytes:       *chSpoolMaxBytes,
			SpoolFrameMaxRows:   *chSpoolFrameMaxRecords,
			SpoolFsyncEvery:     *chSpoolFsync,
			SpoolShutdownDrain:  *chSpoolShutdownDrain,
			SpoolStallThreshold: *chSpoolStallThreshold,
			SpoolWriters:        *chWriters,
			AllowedSourceID:     *sourceID,
		})
		if err != nil {
			log.Error("clickhouse delivery init", "err", err)
			os.Exit(1)
		}
		chDel = &clickhouseDelivery{
			mapper: mapper,
			inner:  inner,
		}
		defer func(d *clickhouseDelivery) {
			d.Close()
			d.LogMetrics()
		}(chDel)
	}

	var healthReporter *flowingest.HealthReporter
	if strings.TrimSpace(*chDSN) != "" && strings.TrimSpace(*chHealthTable) != "" {
		// The daemon is the only place that knows which legs are actually
		// wired: an undeclared leg must read as absent, not as total loss.
		stages := []string{flowingest.StageCollector, flowingest.StageClickHouse}
		if strings.TrimSpace(*iface) != "" {
			stages = append([]string{flowingest.StageInterface}, stages...)
		}
		var sinkPorts []uint16
		if dsts := nfExp.destinations(); len(dsts) > 0 {
			stages = append(stages, flowingest.StageNetFlow)
			sinkPorts = flowingest.LocalSinkPorts(dsts)
		}
		hr, err := flowingest.NewHealthReporter(log, flowingest.HealthReporterConfig{
			DSN:            strings.TrimSpace(*chDSN),
			Table:          strings.TrimSpace(*chHealthTable),
			CollectorID:    strings.TrimSpace(*collectorID),
			SourceID:       *sourceID,
			Daemon:         "xdpflowd",
			Iface:          *iface,
			Stages:         stages,
			LocalSinkPorts: sinkPorts,

			PhyPacketCounters:  splitCSV(*phyPktCounters),
			PhyDiscardCounters: splitCSV(*phyDiscardCounters),
		})
		if err != nil {
			log.Error("health reporter init", "err", err)
			os.Exit(1)
		}
		healthReporter = hr
		if healthReporter != nil {
			defer healthReporter.Close()
		}
	}

	var chFlowCb func([]flowKV, time.Time)
	if chDel != nil {
		chFlowCb = func(flows []flowKV, t time.Time) {
			chDel.enqueue(flows, t)
		}
	}

	if *once {
		time.Sleep(*interval)
		if *jsonOut != "" {
			snap := buildSnapshot(objs, *jsonFlows)
			if err := writeJSONLine(*jsonOut, snap); err != nil {
				log.Error("json-out", "err", err)
				os.Exit(1)
			}
		}
		dumpTop(log, objs, *topN)
		log.Info("shutdown", "reason", "once")
		return
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	healthTicker := time.NewTicker(*healthInterval)
	defer healthTicker.Stop()

	var jsonTicker *time.Ticker
	if *jsonOut != "" {
		jsonTicker = time.NewTicker(jInt)
		defer jsonTicker.Stop()
	}

	// In batch full-drain mode the whole map is drained each tick, so the tick
	// interval IS the active timeout — use -drain-interval (default -nf-active),
	// not the 1 s -nf-scan. The per-key timer path keeps the fine-grained
	// -nf-scan cadence. Applies to both the NetFlow (scanAndExport) and the
	// ClickHouse-only export paths.
	exportEvery := *nfScan
	batchDrain := drainer.BatchEnabled()
	if batchDrain {
		exportEvery = *drainInterval
		if exportEvery <= 0 {
			exportEvery = *nfActive
		}
		log.Info("flow export: batch full-drain", "drain_interval", exportEvery)
	}

	// Userspace flow aggregation: between the frequent BPF drain and the
	// expensive export, fold drain slices back into one entry per flow and emit
	// only on idle/active timeout. Collapses the batch-mode row amplification
	// (one row per flow per drain tick) back to ~one row per real flow. Only
	// meaningful in batch mode with an export sink.
	var agg *flowAggregator
	if batchDrain && *aggEnable && (nfExp != nil || chDel != nil) {
		agg = newFlowAggregator(*aggIdle, *aggActive, *aggMaxEntries)
		log.Info("flow aggregation enabled",
			"idle", *aggIdle,
			"active", *aggActive,
			"max_entries", *aggMaxEntries,
			"drain_interval", exportEvery,
		)
	}

	var exportTicker *time.Ticker
	if nfExp != nil || chDel != nil {
		exportTicker = time.NewTicker(exportEvery)
		defer exportTicker.Stop()
	}

	// The expensive top-N dump walks the full BPF flow map. Decouple it from
	// `interval` so high-cardinality hosts can keep cheap stats printing on the
	// short interval without paying for a full map walk + heap each time.
	var topTicker *time.Ticker
	if *topInterval > 0 && *topN > 0 {
		topTicker = time.NewTicker(*topInterval)
		defer topTicker.Stop()
	}

	// flushFinal writes a last NDJSON snapshot right before exiting — this closes
	// the timing gap with external counters (e.g. /sys/class/net/*/statistics/*)
	// so the accuracy test can compare deltas taken at the same instant.
	flushFinal := func() {
		if *jsonOut == "" {
			return
		}
		snap := buildSnapshot(objs, *jsonFlows)
		if err := writeJSONLine(*jsonOut, snap); err != nil {
			log.Error("json-out final", "err", err)
		}
	}

	// Build channels that may be nil-safe in select (nil channel blocks forever).
	var jsonC, exportC, topC, healthC <-chan time.Time
	if jsonTicker != nil {
		jsonC = jsonTicker.C
	}
	if exportTicker != nil {
		exportC = exportTicker.C
	}
	if topTicker != nil {
		topC = topTicker.C
	}
	if !*once {
		healthC = healthTicker.C
	}

	var prevMapFull, prevInsertErrs, prevQueueDrops, prevNFSendErrs uint64
	var prevCorruptionFrames uint64
	var prevTotalPackets uint64

	for {
		select {
		case <-ctx.Done():
			flushFinal()
			if !*finalFlushFlows {
				log.Info("final flow flush skipped", "reason", "final_flush_disabled")
				if nfExp != nil {
					nfExp.logMetrics()
				}
				log.Info("shutdown")
				return
			}
			if nfExp != nil {
				// Final scan: force-export whatever is still in the map so we
				// don't lose trailing flows when shutting down for A/B swap.
				exported, deleted := nfExp.flushAll(objs, drainer, chFlowCb, agg)
				log.Info("final flush", "exported", exported, "deleted", deleted, "clickhouse_enabled", chDel != nil)
				nfExp.logMetrics()
			} else if chDel != nil {
				if batchDrain {
					receivedAt := time.Now().UTC()
					n, err := drainer.StreamFullBatchDrain(objs, func(chunk []flowKV) error {
						if agg != nil {
							agg.Merge(chunk)
						} else {
							chDel.enqueue(chunk, receivedAt)
						}
						return nil
					})
					if err != nil {
						log.Error("final batch full-drain", "err", err, "drained", n)
					}
					if agg != nil {
						if ready := agg.DrainAll(); len(ready) > 0 {
							chDel.enqueue(ready, receivedAt)
						}
					}
					log.Info("final flush", "exported", n, "deleted", n, "drain_mode", "batch", "clickhouse_enabled", true)
				} else {
					receivedAt := time.Now().UTC()
					exported, deleted, atomicDrained, err := drainer.StreamAll(objs, func(chunk []flowKV) error {
						chDel.enqueue(chunk, receivedAt)
						return nil
					})
					if err != nil {
						log.Error("final timer drain", "err", err, "exported", exported, "deleted", deleted)
					}
					log.Info("final flush", "exported", exported, "deleted", deleted, "atomic_drain", atomicDrained, "clickhouse_enabled", true)
				}
			}
			log.Info("shutdown")
			return
		case <-ticker.C:
			logStats(log, objs)
			if nfExp != nil {
				nfExp.logMetrics()
			}
			if chDel != nil {
				chDel.LogMetrics()
			}
			if drainer != nil {
				atomicCalls, legacyCalls := drainer.Counters()
				log.Info("flow drainer",
					"mode", flowDrainerModeName(drainer.Mode()),
					"batch_enabled", drainer.BatchEnabled(),
					"batch_calls", drainer.BatchCalls(),
					"atomic_calls", atomicCalls,
					"legacy_calls", legacyCalls,
				)
			}
			if agg != nil {
				m := agg.Metrics()
				log.Info("flow aggregator",
					"cached", m.Entries,
					"merged_in", m.MergedIn,
					"exported_out", m.ExportedOut,
					"forced_evicted", m.ForcedEvicted,
				)
			}
		case <-healthC:
			mapFull := readStat(objs, 2)
			mapFullDelta := mapFull - prevMapFull

			// Dedicated, easy-to-grep flow-loss line. map_full is the canonical
			// packet-loss tripwire: a packet whose flow could not be created (or,
			// with the LRU map, could not even be inserted after eviction) is
			// never accounted and never reaches ClickHouse. With LRU this should
			// stay 0; any sustained non-zero delta is real data loss.
			totalPackets := readStat(objs, 0)
			totalDelta := totalPackets - prevTotalPackets
			if mapFullDelta > 0 {
				lossRatio := 0.0
				if totalDelta > 0 {
					lossRatio = float64(mapFullDelta) / float64(totalDelta)
				}
				if lossRatio >= *healthLossRatio {
					log.Error("xdpflowd flow loss",
						"lost_packets", mapFullDelta,
						"total_packets_interval", totalDelta,
						"loss_ratio", lossRatio,
						"loss_ratio_threshold", *healthLossRatio,
						"map_full_total", mapFull,
						"hint", "raise FLOWS_MAP_SIZE or shorten XDP_DRAIN_INTERVAL",
					)
				}
			}
			prevTotalPackets = totalPackets

			insertErrsDelta := uint64(0)
			queueDropsDelta := uint64(0)
			writerLagRows := uint64(0)
			lagSegments := int64(0)
			drainerAge := time.Duration(0)
			chMode := ""
			if chDel != nil {
				ch := chDel.HealthSnapshot()
				chMode = ch.Mode
				insertErrsDelta = ch.InsertErrs - prevInsertErrs
				queueDropsDelta = ch.QueueDrops - prevQueueDrops
				lagSegments = ch.LagSegments
				drainerAge = ch.DrainerProgressAge
				if ch.RecordsQueued > ch.RecordsWritten {
					writerLagRows = ch.RecordsQueued - ch.RecordsWritten
				}
				if ch.RecordsSpooled > ch.RecordsAcked {
					writerLagRows = ch.RecordsSpooled - ch.RecordsAcked
				}
				prevInsertErrs = ch.InsertErrs
				prevQueueDrops = ch.QueueDrops
			}
			nfSendErrs := uint64(0)
			if nfExp != nil {
				nfSendErrs = nfExp.sendErrors()
			}
			nfSendErrsDelta := nfSendErrs - prevNFSendErrs
			if mapFullDelta > 0 ||
				insertErrsDelta > 0 ||
				queueDropsDelta > 0 ||
				nfSendErrsDelta > 0 ||
				lagSegments > *healthSpoolLagSegments ||
				writerLagRows > *healthWriterLagRows ||
				(lagSegments > 0 && drainerAge > *healthDrainerAge) {
				log.Error("xdpflowd health degraded",
					"map_full_delta", mapFullDelta,
					"map_full_total", mapFull,
					"clickhouse_mode", chMode,
					"insert_errs_delta", insertErrsDelta,
					"queue_drops_delta", queueDropsDelta,
					"writer_lag_rows", writerLagRows,
					"writer_lag_threshold", *healthWriterLagRows,
					"lag_segments", lagSegments,
					"lag_segments_threshold", *healthSpoolLagSegments,
					"drainer_progress_age", drainerAge.Truncate(time.Second),
					"drainer_age_threshold", *healthDrainerAge,
					"netflow_send_errs_delta", nfSendErrsDelta,
					"netflow_send_errs_total", nfSendErrs,
				)
			}
			prevMapFull = mapFull
			prevNFSendErrs = nfSendErrs
			if healthReporter != nil {
				chSnap := flowingest.HealthSnapshot{}
				if chDel != nil {
					chSnap = chDel.HealthSnapshot()
				}
				corruptionDelta := chSnap.CorruptionFrames - prevCorruptionFrames
				prevCorruptionFrames = chSnap.CorruptionFrames
				_ = healthReporter.Write(ctx, flowingest.HealthWriteInput{
					XDP: flowingest.XDPMetrics{
						TotalPackets: totalPackets,
						TotalBytes:   readStat(objs, 14),
						MapFull:      mapFull,
						ParseErrors:  readStat(objs, 1),
						NonIPPass:    readStat(objs, 3),
					},
					CH:                     chSnap,
					Exclusions:             exclFilter.Stats(),
					NetFlow:                nfExp.metrics(),
					MapFullDelta:           mapFullDelta,
					InsertErrsDelta:        insertErrsDelta,
					QueueDropsDelta:        queueDropsDelta,
					NFSendErrsDelta:        nfSendErrsDelta,
					SpoolCorruptionDelta:   corruptionDelta,
					LagSegmentsThreshold:   *healthSpoolLagSegments,
					WriterLagRowsThreshold: *healthWriterLagRows,
					DrainerAgeThreshold:    *healthDrainerAge,
				})
			}
		case <-topC:
			dumpTop(log, objs, *topN)
		case <-jsonC:
			snap := buildSnapshot(objs, *jsonFlows)
			if err := writeJSONLine(*jsonOut, snap); err != nil {
				log.Error("json-out", "err", err)
			}
		case <-exportC:
			if nfExp != nil {
				_, _ = nfExp.scanAndExport(objs, drainer, chFlowCb, agg)
			} else if chDel != nil {
				if batchDrain {
					receivedAt := time.Now().UTC()
					n, err := drainer.StreamFullBatchDrain(objs, func(chunk []flowKV) error {
						if agg != nil {
							agg.Merge(chunk)
						} else {
							chDel.enqueue(chunk, receivedAt)
						}
						return nil
					})
					if err != nil {
						log.Error("batch full-drain", "err", err, "drained", n)
					}
					if agg != nil {
						nowMonoNs, _ := readSystemUptimeNs()
						if ready := agg.Collect(nowMonoNs); len(ready) > 0 {
							chDel.enqueue(ready, receivedAt)
						}
					}
					break
				}
				nowMonoNs, err := readSystemUptimeNs()
				if err != nil {
					log.Error("read uptime", "err", err)
					break
				}
				receivedAt := time.Now().UTC()
				exported, deleted, _, err := drainer.StreamExpired(objs, *nfIdle, *nfActive, nowMonoNs, func(chunk []flowKV) error {
					chDel.enqueue(chunk, receivedAt)
					return nil
				})
				if err != nil {
					log.Error("timer drain", "err", err, "exported", exported, "deleted", deleted)
				}
			}
		}
	}
}

// splitCSV trims and splits "a,b,c" into non-empty fields.
func splitCSV(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}
