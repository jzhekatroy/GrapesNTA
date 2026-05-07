//go:build linux

package main

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

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
	mreq := &unix.PacketMreq{
		Ifindex: int32(ifi.Index),
		Type:    unix.PACKET_MR_PROMISC,
	}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, mreq); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("enable promisc %s: %w", ifname, err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 16<<20)

	return fd, nil
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}
