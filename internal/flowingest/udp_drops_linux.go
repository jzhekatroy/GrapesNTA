//go:build linux

package flowingest

import "os"

// ReadUDPSocketDrops sums kernel drop counters of every local socket bound to
// one of ports. observed is false when no such socket exists here, which is the
// normal case for a remote receiver.
func ReadUDPSocketDrops(ports []uint16) (drops uint64, observed bool) {
	if len(ports) == 0 {
		return 0, false
	}
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		for _, port := range ports {
			if _, err := f.Seek(0, 0); err != nil {
				break
			}
			d, ok := parseUDPDrops(f, port)
			if ok {
				observed = true
				drops += d
			}
		}
		_ = f.Close()
	}
	return drops, observed
}
