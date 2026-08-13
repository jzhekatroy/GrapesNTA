// afxdpflowd — AF_XDP wire capture + optional userspace flow aggregation + NetFlow v9.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"xdpflowd/internal/afxdp"
)

func main() {
	ver := flag.Bool("version", false, "print version and exit")
	iface := flag.String("iface", "", "network interface (required)")
	queue := flag.Int("queue", 0, "RX queue id for this socket")
	maxQ := flag.Int("max-queues", 64, "XSK/qidconf map size (>= queue+1)")
	pollMs := flag.Int("poll-ms", 250, "xsk poll timeout in ms; use -1 for 1000ms (interruptible default)")
	stats := flag.Duration("stats", 2*time.Second, "wire_ground_truth JSON on stderr + stats line interval (stdout) when -nf-dst set")
	skb := flag.Bool("skb", false, "use generic XDP (XDP_FLAGS_SKB_MODE), e.g. when native XDP fails on VM")
	umem := flag.Int("umem-frames", 4096, "UMEM frame count (power of 2 recommended)")
	frm := flag.Int("frame-size", 2048, "bytes per UMEM frame")

	// NetFlow v9 (same flags as xdpflowd)
	nfDst := flag.String("nf-dst", "", "NetFlow v9 host:port destinations (comma-separated). Empty = wire counters only.")
	nfActive := flag.Duration("nf-active", 120*time.Second, "NetFlow active timeout")
	nfIdle := flag.Duration("nf-idle", 15*time.Second, "NetFlow idle timeout")
	nfTemplateInterval := flag.Duration("nf-template-interval", 60*time.Second, "template re-send interval")
	nfScan := flag.Duration("nf-scan", 1*time.Second, "flow table scan for export")
	nfSourceID := flag.Uint("nf-source-id", 1, "NetFlow v9 source_id (observation domain)")
	flowMax := flag.Int("flow-map-max", 1_000_000, "max concurrent flows in userspace map (IPv4+IPv6)")

	flag.Parse()
	if *ver {
		fmt.Println("afxdpflowd", afxdp.Version, "— see README / internal/afxdp/doc.go")
		return
	}
	if *iface == "" {
		fmt.Fprintln(os.Stderr, "usage: afxdpflowd -iface <dev> [flags]  (or -version)")
		flag.PrintDefaults()
		os.Exit(2)
	}
	cfg := afxdp.Config{
		Interface:          *iface,
		QueueID:            *queue,
		MaxQueues:          *maxQ,
		PollMs:             *pollMs,
		StatsEvery:         *stats,
		UseSKBMode:         *skb,
		UMEMFrames:         *umem,
		FrameSize:          *frm,
		NFDst:              *nfDst,
		NFActive:           *nfActive,
		NFIdle:             *nfIdle,
		NFTemplateInterval: *nfTemplateInterval,
		NFScan:             *nfScan,
		NFSourceID:         uint32(*nfSourceID),
		FlowMapMax:         *flowMax,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := afxdp.Run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
