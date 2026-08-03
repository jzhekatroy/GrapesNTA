//go:build linux

package flowingest

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Driver counters, not the netdev ones. Under native XDP with XDP_DROP the
// driver frees the packet before it reaches netdev accounting, so
// /sys/class/net/<iface>/statistics/rx_packets counts only what XDP passed
// upstack — on a mirror port that is a rounding error next to the real load.
// The wire-side numbers live in the driver stat table behind ETHTOOL_GSTATS.

const (
	ethtoolGSSetInfo = 0x37
	ethtoolGStrings  = 0x1b
	ethtoolGStats    = 0x1d
	ethSSStats       = 1
	ethGStringLen    = 32
)

type ethtoolIfreq struct {
	name [unix.IFNAMSIZ]byte
	data uintptr
	_    [16]byte
}

func newEthtoolIfreq(iface string) (*ethtoolIfreq, error) {
	if len(iface) == 0 || len(iface) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("ethtool: bad interface name %q", iface)
	}
	ifr := &ethtoolIfreq{}
	copy(ifr.name[:], iface)
	return ifr, nil
}

func ethtoolIoctl(fd int, ifr *ethtoolIfreq, payload unsafe.Pointer) error {
	ifr.data = uintptr(payload)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(ifr)))
	if errno != 0 {
		return errno
	}
	return nil
}

// readEthtoolStats returns the driver stat table of iface keyed by counter name.
func readEthtoolStats(iface string) (map[string]uint64, error) {
	ifr, err := newEthtoolIfreq(iface)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	n, err := ethtoolStatCount(fd, ifr)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	names, err := ethtoolStatNames(fd, ifr, n)
	if err != nil {
		return nil, err
	}
	values, err := ethtoolStatValues(fd, ifr, n)
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint64, n)
	for i, name := range names {
		if name != "" && i < len(values) {
			out[name] = values[i]
		}
	}
	return out, nil
}

// struct ethtool_sset_info { u32 cmd; u32 reserved; u64 sset_mask; u32 data[]; }
func ethtoolStatCount(fd int, ifr *ethtoolIfreq) (int, error) {
	buf := make([]byte, 20)
	*(*uint32)(unsafe.Pointer(&buf[0])) = ethtoolGSSetInfo
	*(*uint64)(unsafe.Pointer(&buf[8])) = 1 << ethSSStats
	if err := ethtoolIoctl(fd, ifr, unsafe.Pointer(&buf[0])); err != nil {
		return 0, err
	}
	// A cleared mask means the driver has no stat set at all.
	if *(*uint64)(unsafe.Pointer(&buf[8])) == 0 {
		return 0, nil
	}
	return int(*(*uint32)(unsafe.Pointer(&buf[16]))), nil
}

// struct ethtool_gstrings { u32 cmd; u32 string_set; u32 len; u8 data[]; }
func ethtoolStatNames(fd int, ifr *ethtoolIfreq, n int) ([]string, error) {
	buf := make([]byte, 12+n*ethGStringLen)
	*(*uint32)(unsafe.Pointer(&buf[0])) = ethtoolGStrings
	*(*uint32)(unsafe.Pointer(&buf[4])) = ethSSStats
	*(*uint32)(unsafe.Pointer(&buf[8])) = uint32(n)
	if err := ethtoolIoctl(fd, ifr, unsafe.Pointer(&buf[0])); err != nil {
		return nil, err
	}
	names := make([]string, n)
	for i := 0; i < n; i++ {
		off := 12 + i*ethGStringLen
		names[i] = cString(buf[off : off+ethGStringLen])
	}
	return names, nil
}

// struct ethtool_stats { u32 cmd; u32 n_stats; u64 data[]; }
func ethtoolStatValues(fd int, ifr *ethtoolIfreq, n int) ([]uint64, error) {
	buf := make([]byte, 8+n*8)
	*(*uint32)(unsafe.Pointer(&buf[0])) = ethtoolGStats
	*(*uint32)(unsafe.Pointer(&buf[4])) = uint32(n)
	if err := ethtoolIoctl(fd, ifr, unsafe.Pointer(&buf[0])); err != nil {
		return nil, err
	}
	values := make([]uint64, n)
	for i := 0; i < n; i++ {
		values[i] = *(*uint64)(unsafe.Pointer(&buf[8+i*8]))
	}
	return values, nil
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
