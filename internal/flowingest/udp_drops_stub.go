//go:build !linux

package flowingest

func ReadUDPSocketDrops(ports []uint16) (drops uint64, observed bool) {
	return 0, false
}
