package afxdp

// Config holds AF_XDP daemon settings. Filled from flags / env; validated before opening sockets.
type Config struct {
	Interface string
	// Queues: empty = all available RX queues, or explicit 0,1,2,...
	QueueList []int
	// NFDests are "host:port" UDP targets (same idea as xdpflowd -nf-dst).
	NFDests []string
	// UMEMFrames is number of UMEM frame slots (power of 2, e.g. 4096, 16384).
	UMEMFrames int
	// FrameSize: typically 2048 (or 4096) bytes per slot.
	FrameSize int
	// UseHugepages: allocate UMEM on huge pages when possible.
	UseHugepages bool
}

// DefaultConfig returns placeholder defaults; will match prod tuning.
func DefaultConfig() Config {
	return Config{
		UMEMFrames: 4096,
		FrameSize:  2048,
	}
}
