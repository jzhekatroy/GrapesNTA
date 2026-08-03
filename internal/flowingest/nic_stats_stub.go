//go:build !linux

package flowingest

func ReadNICStats(iface string) NICStats {
	return NICStats{}
}
