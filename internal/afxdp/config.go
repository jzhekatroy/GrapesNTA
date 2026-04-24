package afxdp

import (
	"fmt"
	"time"
)

// Config is validated in Run; zero values are replaced by defaults.
type Config struct {
	Interface  string
	QueueID    int
	MaxQueues  int  // xsk map / qidconf array size, >= QueueID+1
	PollMs     int  // xsk.Poll timeout; -1 = block
	StatsEvery time.Duration

	UMEMFrames int
	FrameSize  int
	// UseSKBMode forces generic XDP (good for some VMs / when native XDP fails).
	UseSKBMode bool
}

// DefaultConfig returns production-ish defaults for single-queue capture.
func DefaultConfig() Config {
	return Config{
		QueueID:    0,
		MaxQueues:  64,
		PollMs:     250,
		StatsEvery: 2 * time.Second,
		UMEMFrames: 4096,
		FrameSize:  2048,
	}
}

// merged copies defaults into c where unset.
func (c *Config) merged() Config {
	d := DefaultConfig()
	if c.Interface == "" {
		return d // Run will fail
	}
	out := *c
	if out.MaxQueues <= 0 {
		out.MaxQueues = d.MaxQueues
	}
	if out.QueueID < 0 {
		out.QueueID = 0
	}
	if out.MaxQueues < out.QueueID+1 {
		out.MaxQueues = out.QueueID + 1
	}
	if out.PollMs == 0 {
		out.PollMs = d.PollMs
	}
	// Poll(-1) would block past SIGINT; use a finite timeout for ctx cancellation.
	if out.PollMs < 0 {
		out.PollMs = 1000
	}
	if out.StatsEvery <= 0 {
		out.StatsEvery = d.StatsEvery
	}
	if out.UMEMFrames <= 0 {
		out.UMEMFrames = d.UMEMFrames
	}
	if out.FrameSize < 64 {
		out.FrameSize = d.FrameSize
	}
	return out
}

func (c *Config) validate() error {
	if c.Interface == "" {
		return fmt.Errorf("afxdp: interface name is required")
	}
	if c.UMEMFrames < 64 || c.FrameSize < 64 {
		return fmt.Errorf("afxdp: umem/framesize too small")
	}
	// xdp.NewProgram(maxEntries) needs power-of-two or at least > queue id — library uses array map.
	if c.MaxQueues < c.QueueID+1 {
		return fmt.Errorf("afxdp: max-queues %d < queue %d+1", c.MaxQueues, c.QueueID)
	}
	return nil
}
