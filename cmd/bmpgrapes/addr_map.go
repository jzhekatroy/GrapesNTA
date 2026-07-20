package main

import (
	"fmt"
	"net"
	"strings"
)

// parseRouterAddrMap parses "src=canonical,src2=canonical2".
// Keys and values must be valid IP addresses. Duplicate keys overwrite.
// Empty / whitespace-only input returns an empty map (not nil).
func parseRouterAddrMap(s string) (map[string]net.IP, error) {
	out := map[string]net.IP{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}
	// Newlines are separators too (handy in env / heredoc configs).
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", ",")
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Allow trailing comments: "a=b # label"
		if i := strings.IndexByte(part, '#'); i >= 0 {
			part = strings.TrimSpace(part[:i])
			if part == "" {
				continue
			}
		}
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("router-addr-map entry %q: expected src=canonical", part)
		}
		src := net.ParseIP(strings.TrimSpace(key))
		canonical := net.ParseIP(strings.TrimSpace(val))
		if src == nil || canonical == nil {
			return nil, fmt.Errorf("router-addr-map entry %q: invalid IP", part)
		}
		out[ipMapKey(src)] = canonical
	}
	return out, nil
}

func ipMapKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// resolveRouterAddr returns the canonical router IP for CH identity.
// TCP remote is used for allowlist; this remap only affects stored router_addr.
func resolveRouterAddr(remote net.IP, m map[string]net.IP) net.IP {
	if remote == nil {
		return remote
	}
	if len(m) == 0 {
		return remote
	}
	if mapped, ok := m[ipMapKey(remote)]; ok && mapped != nil {
		return mapped
	}
	return remote
}

func routerAddrBytes(ip net.IP) [16]byte {
	var out [16]byte
	if ip == nil {
		return out
	}
	copy(out[:], ip.To16())
	return out
}
