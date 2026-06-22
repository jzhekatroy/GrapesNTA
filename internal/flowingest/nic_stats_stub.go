//go:build !linux

package flowingest

func ReadNICStats(iface string) (rxPackets, rxBytes uint64) {
	return 0, 0
}
