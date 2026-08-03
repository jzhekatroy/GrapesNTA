package flowingest

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
)

// UDP acknowledges nothing, so a collector cannot tell whether an exported
// datagram reached the process on the other end. When that process listens on
// this host, the kernel can: it keeps a per-socket drop counter for datagrams
// it had to discard because the receive buffer was full. That counter is
// independent of both processes and works for any receiver — nfcapd, goflow2,
// or anything else bound to the port.

// parseUDPDrops sums the drop counters of every socket bound to port in
// /proc/net/udp-style content. found reports whether such a socket exists at
// all: "no socket" and "socket with zero drops" are different answers.
func parseUDPDrops(r io.Reader, port uint16) (drops uint64, found bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout
		// inode ref pointer drops
		if len(fields) < 13 {
			continue
		}
		local := fields[1]
		colon := strings.LastIndexByte(local, ':')
		if colon < 0 {
			continue
		}
		p, err := strconv.ParseUint(local[colon+1:], 16, 16)
		if err != nil || uint16(p) != port {
			continue
		}
		found = true
		if d, err := strconv.ParseUint(fields[len(fields)-1], 10, 64); err == nil {
			drops += d
		}
	}
	return drops, found
}

// LocalSinkPorts returns the UDP ports of dsts whose address belongs to this
// host, which are the only ones whose receive socket we can inspect. Remote
// destinations are dropped: for them the honest answer is "not observable",
// not "zero drops".
func LocalSinkPorts(dsts []string) []uint16 {
	if len(dsts) == 0 {
		return nil
	}
	local := localAddrSet()
	seen := make(map[uint16]struct{}, len(dsts))
	out := make([]uint16, 0, len(dsts))
	for _, dst := range dsts {
		host, portStr, err := net.SplitHostPort(strings.TrimSpace(dst))
		if err != nil {
			continue
		}
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || p == 0 {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		if !ip.IsLoopback() {
			if _, ok := local[ip.String()]; !ok {
				continue
			}
		}
		port := uint16(p)
		if _, dup := seen[port]; dup {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	return out
}

func localAddrSet() map[string]struct{} {
	set := make(map[string]struct{})
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return set
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP != nil {
			set[ipnet.IP.String()] = struct{}{}
		}
	}
	return set
}
