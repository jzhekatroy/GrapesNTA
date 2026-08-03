package flowingest

// NICStats holds cumulative receive counters of one network interface.
// Zero values are also what an unreadable counter reports, so treat these as
// signals rather than exact loss accounting.
type NICStats struct {
	RxPackets uint64
	RxBytes   uint64
	RxDropped uint64
	RxErrors  uint64
	RxMissed  uint64
	RxFifo    uint64
}
