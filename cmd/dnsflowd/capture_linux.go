//go:build linux

package main

import (
	"fmt"
	"net"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// ipv4UDPDNSBPF is classic BPF: Ethernet IPv4, UDP, src or dst port 53.
// Single 802.1Q tag is not matched (mirror should deliver untagged IP or extend this filter).
func ipv4UDPDNSBPF() ([]bpf.RawInstruction, error) {
	return bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 8},
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 6},
		bpf.LoadMemShift{Off: 14},
		bpf.LoadIndirect{Off: 14, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 4, SkipFalse: 0},
		bpf.LoadIndirect{Off: 16, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 2, SkipFalse: 0},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 0xffff},
	})
}

func openCapture(ifname string) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("socket AF_PACKET: %w", err)
	}
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	sa := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, &sa); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind %s: %w", ifname, err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 16<<20)

	raw, err := ipv4UDPDNSBPF()
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	sf := make([]unix.SockFilter, len(raw))
	for i, ins := range raw {
		sf[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	fp := unix.SockFprog{Len: uint16(len(sf)), Filter: &sf[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fp); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("SO_ATTACH_FILTER: %w", err)
	}
	return fd, nil
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}
