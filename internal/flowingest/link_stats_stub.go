//go:build !linux

package flowingest

func ReadLinkStats(iface string, packetNames, discardNames []string) LinkStats {
	return LinkStats{}
}
