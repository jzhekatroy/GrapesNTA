//go:build linux

package flowingest

import "strings"

// ReadLinkStats prefers driver counters and falls back to sysfs when the NIC
// exposes no usable stat table. The sysfs fallback deliberately ignores
// rx_dropped: on an XDP interface it counts XDP_DROP verdicts, which is our own
// filtering rather than loss.
func ReadLinkStats(iface string, packetNames, discardNames []string) LinkStats {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return LinkStats{}
	}
	if table, err := readEthtoolStats(iface); err == nil {
		if stats, ok := linkStatsFromTable(table, packetNames, discardNames); ok {
			return stats
		}
	}
	nic := ReadNICStats(iface)
	if nic.RxPackets == 0 && nic.RxMissed == 0 && nic.RxFifo == 0 {
		return LinkStats{}
	}
	return LinkStats{
		RxPackets:  nic.RxPackets,
		RxDiscards: nic.RxMissed + nic.RxFifo,
		Source:     "sysfs",
	}
}
