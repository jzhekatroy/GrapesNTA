//go:build linux

package flowingest

import (
	"os"
	"strconv"
	"strings"
)

func readSysfsCounter(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// ReadNICStats reads cumulative rx counters from /sys/class/net/<iface>/statistics.
func ReadNICStats(iface string) NICStats {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return NICStats{}
	}
	base := "/sys/class/net/" + iface + "/statistics/"
	return NICStats{
		RxPackets: readSysfsCounter(base + "rx_packets"),
		RxBytes:   readSysfsCounter(base + "rx_bytes"),
		RxDropped: readSysfsCounter(base + "rx_dropped"),
		RxErrors:  readSysfsCounter(base + "rx_errors"),
		// Driver-specific: absent on some NICs, which readSysfsCounter reports
		// as 0 — indistinguishable from "no drops", but harmless as a signal.
		RxMissed: readSysfsCounter(base + "rx_missed_errors"),
		RxFifo:   readSysfsCounter(base + "rx_fifo_errors"),
	}
}
