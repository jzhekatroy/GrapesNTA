//go:build linux

package afxdp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/planktonzp/xdp"
	"golang.org/x/sys/unix"
	"xdpflowd/internal/netv9"
)

// Run attaches XDP redirect + AF_XDP socket, counts L2 frames, and optionally
// aggregates flows in userspace and exports NetFlow v9 (same templates as xdpflowd).
func Run(ctx context.Context, c Config) error {
	cfg := c.merged()
	if err := cfg.validate(); err != nil {
		return err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("afxdp: rlimit: %w", err)
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return fmt.Errorf("afxdp: interface %q: %w", cfg.Interface, err)
	}
	ifIndex := iface.Index
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log.Info("afxdpflowd started", "iface", cfg.Interface, "queue", cfg.QueueID, "ifindex", ifIndex, "skb", cfg.UseSKBMode)

	if cfg.UseSKBMode {
		xdp.DefaultXdpFlags = unix.XDP_FLAGS_SKB_MODE
	} else {
		xdp.DefaultXdpFlags = 0
	}

	program, err := xdp.NewProgram(cfg.MaxQueues)
	if err != nil {
		return fmt.Errorf("afxdp: new xdp program: %w", err)
	}

	if err := program.Attach(ifIndex); err != nil {
		_ = program.Close()
		return fmt.Errorf("afxdp: program attach: %w", err)
	}

	opts := &xdp.SocketOptions{
		NumFrames:              cfg.UMEMFrames,
		FrameSize:              cfg.FrameSize,
		FillRingNumDescs:       2048,
		CompletionRingNumDescs: 2048,
		RxRingNumDescs:         2048,
		TxRingNumDescs:         0,
	}

	xsk, err := xdp.NewSocket(ifIndex, cfg.QueueID, opts)
	if err != nil {
		_ = program.Detach(ifIndex)
		_ = program.Close()
		return fmt.Errorf("afxdp: new af_xdp socket: %w", err)
	}

	if err := program.Register(cfg.QueueID, xsk.FD()); err != nil {
		_ = xsk.Close()
		_ = program.Detach(ifIndex)
		_ = program.Close()
		return fmt.Errorf("afxdp: xsk map register: %w", err)
	}
	defer func() {
		_ = program.Unregister(cfg.QueueID)
		_ = xsk.Close()
		_ = program.Detach(ifIndex)
		_ = program.Close()
	}()

	var st Stats
	var exp *netv9.Exporter
	var agg *FlowAgg
	if s := strings.TrimSpace(cfg.NFDst); s != "" {
		dests := splitCSV(s)
		ne, nerr := netv9.NewExporter(log, dests, cfg.NFSourceID, cfg.NFActive, cfg.NFIdle, cfg.NFTemplateInterval)
		if nerr != nil {
			return fmt.Errorf("afxdp: netflow: %w", nerr)
		}
		exp = ne
		defer exp.Close()
		exp.SendTemplate()
		agg = NewFlowAgg(cfg.FlowMapMax, uint32(ifIndex), uint32(cfg.QueueID), &st)
		log.Info("afxdpflowd netflow v9 export enabled",
			"dsts", dests,
			"active_timeout", cfg.NFActive,
			"idle_timeout", cfg.NFIdle,
			"template_interval", cfg.NFTemplateInterval,
			"scan_interval", cfg.NFScan,
			"source_id", cfg.NFSourceID,
			"ifindex", ifIndex,
		)
	}

	pollTo := cfg.PollMs
	tick := time.NewTicker(cfg.StatsEvery)
	defer tick.Stop()
	emitStats := func() {
		if b, jerr := st.MarshalJSONLine(); jerr == nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s\n", b)
		}
	}
	defer func() {
		if exp != nil && agg != nil {
			_ = agg.FlushAll(exp)
			exp.LogMetrics()
		}
		emitStats()
	}()

	// NetFlow scan (idle/active) — same cadence as xdpflowd -nf-scan.
	if exp != nil && agg != nil {
		go func() {
			scanT := time.NewTicker(cfg.NFScan)
			defer scanT.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-scanT.C:
					_ = agg.ScanAndExport(exp)
				}
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			emitStats()
			if exp != nil && agg != nil {
				log.Info("stats", "flows_in_map", agg.FlowsInMap())
				exp.LogMetrics()
			}
		default:
		}

		if n := xsk.NumFreeFillSlots(); n > 0 {
			xsk.Fill(xsk.GetDescs(n, true))
		}

		st.AddPoll()
		numRx, _, perr := xsk.Poll(pollTo)
		if perr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("afxdp: poll: %w", perr)
		}
		if numRx == 0 {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			continue
		}

		descs := xsk.Receive(numRx)
		for i := 0; i < len(descs); i++ {
			d := descs[i]
			buf := xsk.GetFrame(d)
			if d.Len > 0 && int(d.Len) <= len(buf) {
				buf = buf[:d.Len]
			}
			if agg != nil {
				agg.OnFrame(buf)
			} else {
				st.addFrame(len(buf), classifyL2(buf))
			}
		}
	}
}

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
