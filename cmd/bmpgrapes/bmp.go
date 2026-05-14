package main

// BMP protocol parsing per RFC 7854.
//
// Only the message types we care about for the MVP are handled here. The rest
// are skipped using the common-header length so the session stays in sync.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// BMP message types (RFC 7854, section 4).
const (
	bmpMsgRouteMonitoring     = 0
	bmpMsgStatisticsReport    = 1
	bmpMsgPeerDownNotif       = 2
	bmpMsgPeerUpNotif         = 3
	bmpMsgInitiation          = 4
	bmpMsgTermination         = 5
	bmpMsgRouteMirroring      = 6
)

// BMP common header is 6 bytes: version(1) + length(4) + type(1).
const bmpCommonHeaderLen = 6

// BMP per-peer header is 42 bytes (RFC 7854, section 4.2).
const bmpPeerHeaderLen = 42

type bmpCommonHeader struct {
	Version uint8
	Length  uint32
	Type    uint8
}

type bmpPeerHeader struct {
	PeerType         uint8
	PeerFlags        uint8 // V/L/A/O bits
	PeerDistinguisher [8]byte
	PeerAddress      [16]byte // IPv4-mapped if V=0
	PeerAS           uint32
	PeerBGPID        uint32
	TimestampSec     uint32
	TimestampUSec    uint32
}

// IsIPv6 derives from BMP per-peer flags V bit (RFC 7854, 4.2):
// "The V flag indicates that the Peer address is an IPv6 address.
//  For IPv4 peers, this is set to 0."
func (h bmpPeerHeader) IsIPv6() bool {
	return h.PeerFlags&0x80 != 0
}

func (h bmpPeerHeader) Timestamp() time.Time {
	if h.TimestampSec == 0 && h.TimestampUSec == 0 {
		return time.Time{}
	}
	return time.Unix(int64(h.TimestampSec), int64(h.TimestampUSec)*1000).UTC()
}

func readFull(r io.Reader, buf []byte) error {
	_, err := io.ReadFull(r, buf)
	return err
}

func readBMPCommonHeader(r io.Reader) (bmpCommonHeader, error) {
	var h bmpCommonHeader
	buf := make([]byte, bmpCommonHeaderLen)
	if err := readFull(r, buf); err != nil {
		return h, err
	}
	h.Version = buf[0]
	h.Length = binary.BigEndian.Uint32(buf[1:5])
	h.Type = buf[5]
	if h.Version != 3 {
		return h, fmt.Errorf("unsupported BMP version %d", h.Version)
	}
	if h.Length < bmpCommonHeaderLen {
		return h, fmt.Errorf("BMP message length %d smaller than header", h.Length)
	}
	return h, nil
}

// readBMPMessage reads a full BMP message (excluding the already-consumed
// common header) into a fixed-size byte slice.
func readBMPBody(r io.Reader, h bmpCommonHeader) ([]byte, error) {
	bodyLen := int(h.Length) - bmpCommonHeaderLen
	if bodyLen < 0 {
		return nil, errors.New("negative BMP body length")
	}
	if bodyLen == 0 {
		return nil, nil
	}
	body := make([]byte, bodyLen)
	if err := readFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

func parseBMPPeerHeader(body []byte) (bmpPeerHeader, []byte, error) {
	var ph bmpPeerHeader
	if len(body) < bmpPeerHeaderLen {
		return ph, nil, fmt.Errorf("BMP per-peer header truncated: %d", len(body))
	}
	ph.PeerType = body[0]
	ph.PeerFlags = body[1]
	copy(ph.PeerDistinguisher[:], body[2:10])
	copy(ph.PeerAddress[:], body[10:26])
	ph.PeerAS = binary.BigEndian.Uint32(body[26:30])
	ph.PeerBGPID = binary.BigEndian.Uint32(body[30:34])
	ph.TimestampSec = binary.BigEndian.Uint32(body[34:38])
	ph.TimestampUSec = binary.BigEndian.Uint32(body[38:42])
	return ph, body[bmpPeerHeaderLen:], nil
}

// PeerUp body after the per-peer header: local addr (16) + local port (2)
// + remote port (2) + sent OPEN + received OPEN.
type bmpPeerUpInfo struct {
	LocalAddress      [16]byte
	LocalPort         uint16
	RemotePort        uint16
	SentOpenMsg       []byte
	ReceivedOpenMsg   []byte
}

func parseBMPPeerUp(body []byte) (bmpPeerUpInfo, error) {
	var info bmpPeerUpInfo
	if len(body) < 20 {
		return info, fmt.Errorf("peer up truncated: %d", len(body))
	}
	copy(info.LocalAddress[:], body[0:16])
	info.LocalPort = binary.BigEndian.Uint16(body[16:18])
	info.RemotePort = binary.BigEndian.Uint16(body[18:20])
	rest := body[20:]

	// Two BGP OPEN messages back-to-back. We rely on the BGP marker+length to
	// peel them off without ever parsing OPEN body in the MVP.
	first, after, err := peelBGPMessage(rest)
	if err != nil {
		return info, fmt.Errorf("peer up sent OPEN: %w", err)
	}
	info.SentOpenMsg = first
	if len(after) > 0 {
		second, _, err := peelBGPMessage(after)
		if err != nil {
			return info, fmt.Errorf("peer up received OPEN: %w", err)
		}
		info.ReceivedOpenMsg = second
	}
	return info, nil
}

// BGP message header: marker(16) + length(2) + type(1).
const bgpHeaderLen = 19

func peelBGPMessage(buf []byte) (msg []byte, rest []byte, err error) {
	if len(buf) < bgpHeaderLen {
		return nil, nil, fmt.Errorf("BGP message truncated: %d", len(buf))
	}
	length := binary.BigEndian.Uint16(buf[16:18])
	if int(length) > len(buf) {
		return nil, nil, fmt.Errorf("BGP length %d exceeds buffer %d", length, len(buf))
	}
	return buf[:length], buf[length:], nil
}

// peerAddressNetIP converts the IPv4-mapped or IPv6 16-byte form to a printable address.
func peerAddressNetIP(addr [16]byte, isIPv6 bool) string {
	if !isIPv6 {
		// Last 4 bytes hold the IPv4 address per RFC 7854 4.2.
		ip := net.IPv4(addr[12], addr[13], addr[14], addr[15])
		return ip.String()
	}
	return net.IP(addr[:]).String()
}
