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
func ReadNICStats(iface string) (rxPackets, rxBytes uint64) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return 0, 0
	}
	base := "/sys/class/net/" + iface + "/statistics/"
	return readSysfsCounter(base + "rx_packets"), readSysfsCounter(base + "rx_bytes")
}
