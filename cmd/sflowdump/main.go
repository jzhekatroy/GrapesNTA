// sflowdump — read-only diagnostic tool for inspecting a live sFlow v5 stream.
//
// It fully decodes every sample and record type (flow, counter, extended
// switch/router/gateway) — including the parts that flowcollectord currently
// drops — prints a detailed breakdown for the first N datagrams, and always
// prints a summary of what the stream actually contains. It NEVER writes to
// ClickHouse and does not touch the production collector.
//
// Modes:
//   live:  sflowdump -listen 0.0.0.0:6343 -count 200
//   pcap:  sflowdump -pcap capture.pcap
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:6343", "UDP listen address for live capture")
	pcapPath := flag.String("pcap", "", "read datagrams from a .pcap file instead of listening (UDP payloads only)")
	count := flag.Int("count", 200, "stop after this many datagrams (live mode; 0 = run until Ctrl-C)")
	printN := flag.Int("print", 20, "tree mode: print full decode for the first N datagrams (rest only feed the summary)")
	flat := flag.Bool("flat", false, "print one compact line per sampled packet (switch/exporter/vlan/rate/MAC/IP:port) instead of the tree")
	flag.Parse()

	sum := newSummary()
	dec := NewDecoder(os.Stdout, sum, *printN, *flat)

	if *pcapPath != "" {
		if err := runPcap(*pcapPath, dec); err != nil {
			fmt.Fprintln(os.Stderr, "pcap:", err)
			os.Exit(1)
		}
	} else {
		runLive(*listen, *count, dec)
	}
	printSummary(os.Stdout, sum)
}

func runLive(addr string, count int, dec *Decoder) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	defer pc.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "\n(interrupted, printing summary…)")
		_ = pc.SetReadDeadline(time.Now())
	}()

	fmt.Fprintf(os.Stderr, "listening on %s (Ctrl-C to stop)…\n", addr)
	buf := make([]byte, 65535)
	n := 0
	for {
		nb, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		cp := make([]byte, nb)
		copy(cp, buf[:nb])
		dec.Datagram(cp, src.String(), time.Now())
		n++
		if count > 0 && n >= count {
			fmt.Fprintf(os.Stderr, "reached count=%d, stopping.\n", count)
			return
		}
	}
}

func runPcap(path string, dec *Decoder) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return err
	}
	linkType := r.LinkType()
	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		pkt := gopacket.NewPacket(data, linkType, gopacket.Lazy)
		udpLayer := pkt.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp, _ := udpLayer.(*layers.UDP)
		if len(udp.Payload) == 0 {
			continue
		}
		src := ""
		if nl := pkt.NetworkLayer(); nl != nil {
			src = fmt.Sprintf("%s:%d", nl.NetworkFlow().Src(), udp.SrcPort)
		}
		dec.Datagram(udp.Payload, src, time.Now())
	}
	return nil
}

func printSummary(w *os.File, s *Summary) {
	fmt.Fprintln(w, "\n════════════════════ SUMMARY ════════════════════")
	fmt.Fprintf(w, "datagrams: %d  (bad/non-v5: %d)\n", s.Datagrams, s.BadDatagrams)

	fmt.Fprintln(w, "\nagents (exporters):")
	for _, kv := range sortU64Str(s.Agents) {
		fmt.Fprintf(w, "  %-40s %d\n", kv.k, kv.v)
	}

	fmt.Fprintln(w, "\nsample types:")
	for _, kv := range sortU64(s.SampleTypes) {
		fmt.Fprintf(w, "  %-24s %d\n", sampleTypeName(kv.k), kv.v)
	}

	if len(s.FlowRecords) > 0 {
		fmt.Fprintln(w, "\nflow records:")
		for _, kv := range sortU64(s.FlowRecords) {
			fmt.Fprintf(w, "  %-24s %d\n", flowRecordName(kv.k), kv.v)
		}
	}
	if len(s.CounterRecs) > 0 {
		fmt.Fprintln(w, "\ncounter records:")
		for _, kv := range sortU64(s.CounterRecs) {
			fmt.Fprintf(w, "  %-24s %d\n", counterRecordName(kv.k), kv.v)
		}
	}

	fmt.Fprintln(w, "\nsampling rates (1/N):")
	for _, kv := range sortU64(s.SamplingRate) {
		fmt.Fprintf(w, "  1/%-10d %d samples\n", kv.k, kv.v)
	}

	if len(s.HeaderProto) > 0 {
		fmt.Fprintln(w, "\nheader protocols:")
		for _, kv := range sortU64(s.HeaderProto) {
			fmt.Fprintf(w, "  %-24s %d\n", headerProtoName(kv.k), kv.v)
		}
		fmt.Fprintf(w, "\nframe_length  min=%d max=%d\n", cleanMin(s.FrameLenMin), s.FrameLenMax)
		fmt.Fprintf(w, "header_length min=%d max=%d  (truncated samples: %d)\n",
			cleanMin(s.HeaderLenMin), s.HeaderLenMax, s.Truncated)
	}

	if len(s.EtherTypes) > 0 {
		fmt.Fprintln(w, "\nethertypes:")
		for _, kv := range sortU64(s.EtherTypes) {
			fmt.Fprintf(w, "  0x%04x %s  %d\n", kv.k, etherTypeName(kv.k), kv.v)
		}
	}
	if len(s.L3Protos) > 0 {
		fmt.Fprintln(w, "\nL4 protocols:")
		for _, kv := range sortU64(s.L3Protos) {
			fmt.Fprintf(w, "  %-24s %d\n", protoName(kv.k), kv.v)
		}
	}
	if len(s.VLANs) > 0 {
		fmt.Fprintln(w, "\nVLANs seen:")
		for _, kv := range sortU16(s.VLANs) {
			fmt.Fprintf(w, "  vlan %-6d %d\n", kv.k, kv.v)
		}
	}
	printTopPorts(w, "top destination ports", s.TopDstPorts)
	printTopPorts(w, "top source ports", s.TopSrcPorts)
	fmt.Fprintln(w, "══════════════════════════════════════════════════")
}

func printTopPorts(w *os.File, title string, m map[uint16]uint64) {
	if len(m) == 0 {
		return
	}
	kvs := sortU16(m)
	if len(kvs) > 15 {
		kvs = kvs[:15]
	}
	fmt.Fprintf(w, "\n%s:\n", title)
	for _, kv := range kvs {
		fmt.Fprintf(w, "  %-6d %-16s %d\n", kv.k, portName(kv.k), kv.v)
	}
}

func cleanMin(v uint32) uint32 {
	if v == ^uint32(0) {
		return 0
	}
	return v
}

// ── sorting helpers ───────────────────────────────────────────────────────

type kvU64 struct {
	k uint32
	v uint64
}
type kvU16 struct {
	k uint16
	v uint64
}
type kvStr struct {
	k string
	v uint64
}

func sortU64(m map[uint32]uint64) []kvU64 {
	out := make([]kvU64, 0, len(m))
	for k, v := range m {
		out = append(out, kvU64{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].v > out[j].v })
	return out
}

func sortU16(m map[uint16]uint64) []kvU16 {
	out := make([]kvU16, 0, len(m))
	for k, v := range m {
		out = append(out, kvU16{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].v > out[j].v })
	return out
}

func sortU64Str(m map[string]uint64) []kvStr {
	out := make([]kvStr, 0, len(m))
	for k, v := range m {
		out = append(out, kvStr{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].v > out[j].v })
	return out
}

// ── naming helpers for the summary ────────────────────────────────────────

func sampleTypeName(f uint32) string {
	switch f {
	case sampleFlow:
		return "flow(1)"
	case sampleCounter:
		return "counter(2)"
	case sampleFlowExp:
		return "flow-expanded(3)"
	case sampleCounterExp:
		return "counter-expanded(4)"
	default:
		return fmt.Sprintf("format-%d", f)
	}
}

func flowRecordName(f uint32) string {
	switch f {
	case frRawHeader:
		return "raw-header(1)"
	case frSampledEthernet:
		return "sampled-ethernet(2)"
	case frSampledIPv4:
		return "sampled-ipv4(3)"
	case frSampledIPv6:
		return "sampled-ipv6(4)"
	case frExtSwitch:
		return "ext-switch(1001)"
	case frExtRouter:
		return "ext-router(1002)"
	case frExtGateway:
		return "ext-gateway(1003)"
	case frExtUser:
		return "ext-user(1004)"
	case frExtMPLS:
		return "ext-mpls(1006)"
	case frExtNAT:
		return "ext-nat(1007)"
	default:
		return fmt.Sprintf("flow-format-%d", f)
	}
}

func counterRecordName(f uint32) string {
	switch f {
	case crGenericIf:
		return "generic-if(1)"
	case crEthernet:
		return "ethernet(2)"
	case crVLAN:
		return "vlan(5)"
	case crProcessor:
		return "processor(1001)"
	default:
		return fmt.Sprintf("counter-format-%d", f)
	}
}

func etherTypeName(e uint32) string {
	switch e {
	case ethTypeIPv4:
		return "IPv4"
	case ethTypeIPv6:
		return "IPv6"
	case ethTypeARP:
		return "ARP"
	default:
		return ""
	}
}

func portName(p uint16) string {
	switch p {
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 123:
		return "NTP"
	case 161:
		return "SNMP"
	case 443:
		return "HTTPS"
	case 19:
		return "CHARGEN"
	case 111:
		return "portmap"
	case 389:
		return "LDAP"
	case 1900:
		return "SSDP"
	case 11211:
		return "memcached"
	default:
		return ""
	}
}
