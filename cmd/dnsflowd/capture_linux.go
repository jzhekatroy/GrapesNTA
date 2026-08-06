//go:build linux

package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type packetCapture struct {
	handle *pcap.Handle
}

type packetCaptureStats struct {
	packetsReceived  int
	packetsDropped   int
	packetsIfDropped int
}

// openPacketCapture uses libpcap, matching tcpdump's capture path on the host.
// The kernel BPF filter keeps high-volume mirror traffic out of userspace.
func openPacketCapture(ifname string) (*packetCapture, error) {
	const (
		snapLen = 65535
		promisc = true
		bufferSize = 128 << 20
	)
	inactive, err := pcap.NewInactiveHandle(ifname)
	if err != nil {
		return nil, fmt.Errorf("pcap inactive %q: %w", ifname, err)
	}
	defer inactive.CleanUp()
	if err := inactive.SetSnapLen(snapLen); err != nil {
		return nil, fmt.Errorf("pcap set snaplen: %w", err)
	}
	if err := inactive.SetPromisc(promisc); err != nil {
		return nil, fmt.Errorf("pcap set promisc: %w", err)
	}
	if err := inactive.SetTimeout(250 * time.Millisecond); err != nil {
		return nil, fmt.Errorf("pcap set timeout: %w", err)
	}
	if err := inactive.SetBufferSize(bufferSize); err != nil {
		return nil, fmt.Errorf("pcap set buffer size: %w", err)
	}
	// Don't enable immediate mode: it wakes userspace per packet and burns CPU
	// on busy mirror ports. The 250ms read timeout already gives reasonable
	// batching for DNS volumes.
	h, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("pcap activate %q: %w", ifname, err)
	}
	// port 53 covers IPv4/IPv6 and UDP/TCP so we can measure blind spots
	// (IPv6 and TCP DNS) that the previous "ip and udp port 53" filter hid.
	// Only IPv4/UDP is parsed into dns_log; other classes are counted and dropped.
	if err := h.SetBPFFilter("port 53"); err != nil {
		h.Close()
		return nil, fmt.Errorf("pcap set DNS BPF filter: %w", err)
	}
	return &packetCapture{handle: h}, nil
}

func (c *packetCapture) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return c.handle.ReadPacketData()
}

func (c *packetCapture) LinkType() layers.LinkType {
	return c.handle.LinkType()
}

func (c *packetCapture) LinkTypeName() string {
	return pcap.DatalinkValToName(int(c.handle.LinkType()))
}

func (c *packetCapture) Stats() (packetCaptureStats, error) {
	stats, err := c.handle.Stats()
	if err != nil {
		return packetCaptureStats{}, err
	}
	return packetCaptureStats{
		packetsReceived:  stats.PacketsReceived,
		packetsDropped:   stats.PacketsDropped,
		packetsIfDropped: stats.PacketsIfDropped,
	}, nil
}

func (c *packetCapture) Close() {
	c.handle.Close()
}
