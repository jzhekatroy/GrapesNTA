// afxdpflowd — AF_XDP wire capture + ground-truth counters (for accuracy tests vs sysfs / NetFlow).
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
	stats := flag.Duration("stats", 2*time.Second, "interval for wire_ground_truth JSON on stderr")
	skb := flag.Bool("skb", false, "use generic XDP (XDP_FLAGS_SKB_MODE), e.g. when native XDP fails on VM")
	umem := flag.Int("umem-frames", 4096, "UMEM frame count (power of 2 recommended)")
	frm := flag.Int("frame-size", 2048, "bytes per UMEM frame")
	flag.Parse()
	if *ver {
		fmt.Println("afxdpflowd", afxdp.Version, "— wire_ground_truth JSON on stderr; see scripts/afxdp_wire_accuracy.sh")
		return
	}
	if *iface == "" {
		fmt.Fprintln(os.Stderr, "usage: afxdpflowd -iface <dev> [flags]  (or -version)")
		flag.PrintDefaults()
		os.Exit(2)
	}
	cfg := afxdp.Config{
		Interface:  *iface,
		QueueID:    *queue,
		MaxQueues:  *maxQ,
		PollMs:     *pollMs,
		StatsEvery: *stats,
		UseSKBMode: *skb,
		UMEMFrames: *umem,
		FrameSize:  *frm,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := afxdp.Run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
