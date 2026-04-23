// xdpflowd — userspace daemon: load XDP program, attach, read flow map, optional JSON dumps.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"xdpflowd/internal/loader"
)

// FlowKey must match struct flow_key in bpf/xdp_flow.c (packed, 40 bytes).
type FlowKey struct {
	SrcAddr   [16]byte
	DstAddr   [16]byte
	SrcPort   uint16
	DstPort   uint16
	VLANID    uint16
	Proto     uint8
	IPVersion uint8
}

// FlowValue must match struct flow_value in bpf/xdp_flow.c (packed, 64 bytes).
type FlowValue struct {
	Packets       uint64
	Bytes         uint64
	FirstSeenNs   uint64
	LastSeenNs    uint64
	IngressIf     uint32
	RxQueue       uint32
	TCPSynCount   uint32
	TCPRstCount   uint32
	TCPFinCount   uint32
	TCPFlagsOR    uint8
	Tos           uint8
	TTLMin        uint8
	TTLMax        uint8
	PktLenMin     uint16
	PktLenMax     uint16
	IPFragCount   uint16
	_             [2]byte
}

type jsonSnapshot struct {
	TsUnixNs int64 `json:"ts_unix_ns"`
	Stats    struct {
		TotalPackets uint64 `json:"total_packets"`
		ParseErrors  uint64 `json:"parse_errors"`
		MapFull      uint64 `json:"map_full"`
	} `json:"stats"`
	Aggregate struct {
		FlowsInMap      int    `json:"flows_in_map"`
		SumFlowPackets  uint64 `json:"sum_flow_packets"`
		SumFlowBytes    uint64 `json:"sum_flow_bytes"`
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
	IPFragCount uint16 `json:"ip_frag_count"`
}

func readStat(objs *loader.Objects, idx uint32) uint64 {
	var buf [8]byte
	if err := objs.Stats.Lookup(idx, buf[:]); err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(buf[:])
}

func zeroStats(objs *loader.Objects) {
	var z uint64
	var k uint32
	for k = 0; k < 3; k++ {
		_ = objs.Stats.Update(k, z, 0)
	}
}

func buildSnapshot(objs *loader.Objects, includeFlows bool) jsonSnapshot {
	var snap jsonSnapshot
	snap.TsUnixNs = time.Now().UnixNano()
	snap.Stats.TotalPackets = readStat(objs, 0)
	snap.Stats.ParseErrors = readStat(objs, 1)
	snap.Stats.MapFull = readStat(objs, 2)

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

func dumpTop(log *slog.Logger, objs *loader.Objects, topN int) {
	type row struct {
		k FlowKey
		v FlowValue
	}
	var rows []row
	var k FlowKey
	var v FlowValue
	iter := objs.Flows.Iterate()
	for iter.Next(&k, &v) {
		rows = append(rows, row{k, v})
	}
	_ = iter.Err()
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].v.Bytes > rows[j].v.Bytes
	})
	if topN > len(rows) {
		topN = len(rows)
	}
	log.Info("stats",
		"flows_in_map", len(rows),
		"total_packets", readStat(objs, 0),
		"parse_errors", readStat(objs, 1),
		"map_full", readStat(objs, 2),
	)
	for i := 0; i < topN; i++ {
		r := rows[i]
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
	bpfObj := flag.String("bpf", "bpf/xdp_flow.o", "path to compiled BPF ELF (clang -target bpf)")
	iface := flag.String("iface", "ens18", "interface to attach XDP to")
	mode := flag.String("mode", "native", "XDP mode: native|generic")
	topN := flag.Int("top", 15, "show top N flows by bytes (log mode)")
	interval := flag.Duration("interval", 5*time.Second, "stats / JSON dump interval")
	jsonOut := flag.String("json-out", "", "append NDJSON snapshots to this file")
	jsonInterval := flag.Duration("json-interval", 0, "JSON dump interval (defaults to -interval)")
	jsonFlows := flag.Bool("json-include-flows", false, "include per-flow array in JSON (large)")
	once := flag.Bool("once", false, "attach, wait one -interval, write one JSON line if -json-out set, print top once, then exit")
	flag.Parse()

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

	objs, err := loader.LoadObjects(*bpfObj)
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

	log.Info("xdpflowd started", "iface", *iface, "mode", *mode, "ifindex", ifi.Index)

	jInt := *jsonInterval
	if jInt == 0 {
		jInt = *interval
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

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

	var jsonTicker *time.Ticker
	if *jsonOut != "" {
		jsonTicker = time.NewTicker(jInt)
		defer jsonTicker.Stop()
	}

	for {
		if jsonTicker != nil {
			select {
			case <-ctx.Done():
				log.Info("shutdown")
				return
			case <-ticker.C:
				dumpTop(log, objs, *topN)
			case <-jsonTicker.C:
				snap := buildSnapshot(objs, *jsonFlows)
				if err := writeJSONLine(*jsonOut, snap); err != nil {
					log.Error("json-out", "err", err)
				}
			}
		} else {
			select {
			case <-ctx.Done():
				log.Info("shutdown")
				return
			case <-ticker.C:
				dumpTop(log, objs, *topN)
			}
		}
	}
}
