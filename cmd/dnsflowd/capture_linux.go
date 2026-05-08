//go:build linux

package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket/afpacket"
)

// openRingCapture opens a TPACKET_V3 mmap RX ring (same mechanism as tcpdump/libpcap).
// Plain AF_PACKET read() drops most packets on busy mirror ports; the ring buffers bulk delivery.
func openRingCapture(ifname string) (*afpacket.TPacket, error) {
	const (
		frameSize = afpacket.DefaultFrameSize // 4096
		blockSize = afpacket.DefaultBlockSize // frameSize * 128 = 512 KiB per block
		numBlocks = 256                       // 256 * 512 KiB ≈ 128 MiB ring
	)
	h, err := afpacket.NewTPacket(
		afpacket.OptInterface(ifname),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		afpacket.OptFrameSize(frameSize),
		afpacket.OptBlockSize(blockSize),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptPollTimeout(250*time.Millisecond),
	)
	if err != nil {
		return nil, fmt.Errorf("afpacket TPACKET_V3 %q: %w", ifname, err)
	}
	return h, nil
}
