package flowingest

import "strings"

// LinkStats is the wire-side view of the capture interface: what the port
// actually received and what it had to throw away before anyone could look at
// it. Source records where the numbers came from, because "no loss" and "we
// cannot read this NIC" must not look the same on a diagnostics screen.
type LinkStats struct {
	RxPackets  uint64
	RxDiscards uint64
	Source     string
}

// Counter names differ per driver, so each role carries a candidate list. The
// first name present in the driver table wins; an unknown NIC simply yields no
// source rather than breaking the chain.
var (
	DefaultLinkPacketCounters = []string{
		"rx_packets_phy",  // mlx5
		"rx_good_packets", // mlx4, some others
		"port.rx_unicast", // ice
		"rx_unicast",      // i40e
	}
	DefaultLinkDiscardCounters = []string{
		"rx_discards_phy",    // mlx5
		"rx_missed_errors",   // generic
		"rx_no_buffer_count", // igb/ixgbe
		"port.rx_dropped",    // ice
		"rx_dropped",         // generic fallback
	}
)

// pickCounter returns the first candidate present in table.
func pickCounter(table map[string]uint64, candidates []string) (name string, value uint64, ok bool) {
	for _, c := range candidates {
		if v, present := table[c]; present {
			return c, v, true
		}
	}
	return "", 0, false
}

func linkStatsFromTable(table map[string]uint64, packetNames, discardNames []string) (LinkStats, bool) {
	if len(table) == 0 {
		return LinkStats{}, false
	}
	if len(packetNames) == 0 {
		packetNames = DefaultLinkPacketCounters
	}
	if len(discardNames) == 0 {
		discardNames = DefaultLinkDiscardCounters
	}
	pktName, pkts, pktOK := pickCounter(table, packetNames)
	discName, disc, discOK := pickCounter(table, discardNames)
	if !pktOK && !discOK {
		return LinkStats{}, false
	}
	used := make([]string, 0, 2)
	if pktOK {
		used = append(used, pktName)
	}
	if discOK {
		used = append(used, discName)
	}
	return LinkStats{
		RxPackets:  pkts,
		RxDiscards: disc,
		Source:     "ethtool:" + strings.Join(used, "+"),
	}, true
}
