//go:build linux

package afxdp

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/planktonzp/xdp"
	"golang.org/x/sys/unix"
)

// Run attaches the stock libbpf-style XDP redirect program, opens one AF_XDP
// socket on (iface, queue), and counts every L2 frame for wire_ground_truth JSON.
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
	pollTo := cfg.PollMs
	tick := time.NewTicker(cfg.StatsEvery)
	defer tick.Stop()
	emitStats := func() {
		if b, jerr := st.MarshalJSONLine(); jerr == nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s\n", b)
		}
	}
	defer emitStats()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			emitStats()
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
			st.addFrame(len(buf), classifyL2(buf))
		}
	}
}
