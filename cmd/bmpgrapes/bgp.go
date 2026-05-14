package main

// Minimal BGP UPDATE parser for BMP route-monitoring messages.
//
// Scope for MVP:
//   - IPv4 unicast NLRI (announce + withdraw) from the legacy UPDATE format
//   - IPv6 unicast NLRI via MP_REACH_NLRI / MP_UNREACH_NLRI
//   - Path attributes we extract: ORIGIN (rough), AS_PATH (4-byte ASNs),
//     NEXT_HOP (IPv4), MP_REACH_NLRI / MP_UNREACH_NLRI, MED, LOCAL_PREF.
//
// We deliberately do NOT support:
//   - 2-octet AS_PATH (relevant only for ancient peers without 4-byte ASN).
//     With 2-octet ASNs we still parse path length but coerce values to UInt32.
//   - VPNv4/VPNv6, BGP-LS, EVPN, FlowSpec.
//
// Any unknown attribute is preserved as opaque bytes and skipped.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	bgpMsgOpen          = 1
	bgpMsgUpdate        = 2
	bgpMsgNotification  = 3
	bgpMsgKeepalive     = 4
)

const (
	bgpAttrOrigin       = 1
	bgpAttrASPath       = 2
	bgpAttrNextHop      = 3
	bgpAttrMED          = 4
	bgpAttrLocalPref    = 5
	bgpAttrCommunities  = 8
	bgpAttrMPReachNLRI  = 14
	bgpAttrMPUnreachNLRI = 15
	bgpAttrExtCommunities = 16
	bgpAttrAS4Path      = 17
	bgpAttrLargeCommunities = 32
)

const (
	asPathSegmentSet      = 1
	asPathSegmentSequence = 2
)

// bgpUpdate is what the parser extracts.
type bgpUpdate struct {
	WithdrawnV4 []nlri
	AnnouncedV4 []nlri
	WithdrawnV6 []nlri
	AnnouncedV6 []nlri
	NextHopV4   [4]byte
	HaveNextHopV4 bool
	NextHopV6   [16]byte
	HaveNextHopV6 bool
	ASPath      []uint32
	Origin      uint8
	MED         uint32
	LocalPref   uint32
}

type nlri struct {
	PrefixLen uint8
	Prefix    [16]byte // network byte order, padded with zeros
	Family    uint8    // 4 = IPv4, 6 = IPv6
}

// parseBGPUpdate parses a single BGP UPDATE message including the BGP header.
func parseBGPUpdate(msg []byte) (bgpUpdate, error) {
	var u bgpUpdate
	if len(msg) < bgpHeaderLen {
		return u, fmt.Errorf("BGP message too small: %d", len(msg))
	}
	if msg[18] != bgpMsgUpdate {
		return u, fmt.Errorf("expected BGP UPDATE, got type=%d", msg[18])
	}
	body := msg[bgpHeaderLen:]

	if len(body) < 2 {
		return u, errors.New("UPDATE body missing withdrawn length")
	}
	wlen := binary.BigEndian.Uint16(body[0:2])
	body = body[2:]
	if int(wlen) > len(body) {
		return u, fmt.Errorf("withdrawn length %d exceeds body %d", wlen, len(body))
	}
	wBytes := body[:wlen]
	body = body[wlen:]
	withdrawn, err := parseNLRI(wBytes, 4)
	if err != nil {
		return u, fmt.Errorf("parse withdrawn v4: %w", err)
	}
	u.WithdrawnV4 = withdrawn

	if len(body) < 2 {
		return u, errors.New("UPDATE body missing total attr length")
	}
	alen := binary.BigEndian.Uint16(body[0:2])
	body = body[2:]
	if int(alen) > len(body) {
		return u, fmt.Errorf("attr length %d exceeds body %d", alen, len(body))
	}
	attrBytes := body[:alen]
	body = body[alen:]

	if err := parseAttributes(attrBytes, &u); err != nil {
		return u, fmt.Errorf("parse attributes: %w", err)
	}

	announced, err := parseNLRI(body, 4)
	if err != nil {
		return u, fmt.Errorf("parse announced v4: %w", err)
	}
	u.AnnouncedV4 = announced
	return u, nil
}

// parseNLRI decodes a sequence of <prefix-length><prefix-bytes> entries.
func parseNLRI(buf []byte, family uint8) ([]nlri, error) {
	maxBits := 32
	if family == 6 {
		maxBits = 128
	}
	var out []nlri
	for len(buf) > 0 {
		plen := buf[0]
		if int(plen) > maxBits {
			return nil, fmt.Errorf("NLRI prefix length %d out of range", plen)
		}
		buf = buf[1:]
		pbytes := (int(plen) + 7) / 8
		if pbytes > len(buf) {
			return nil, fmt.Errorf("NLRI prefix %d bytes exceeds buffer %d", pbytes, len(buf))
		}
		var p [16]byte
		copy(p[:pbytes], buf[:pbytes])
		if rem := int(plen) % 8; rem != 0 && pbytes > 0 {
			p[pbytes-1] &= byte(0xff << uint(8-rem))
		}
		out = append(out, nlri{PrefixLen: plen, Prefix: p, Family: family})
		buf = buf[pbytes:]
	}
	return out, nil
}

func parseAttributes(buf []byte, u *bgpUpdate) error {
	for len(buf) > 0 {
		if len(buf) < 2 {
			return errors.New("attribute header truncated")
		}
		flags := buf[0]
		typ := buf[1]
		buf = buf[2:]
		var alen int
		if flags&0x10 != 0 {
			if len(buf) < 2 {
				return errors.New("extended attribute length truncated")
			}
			alen = int(binary.BigEndian.Uint16(buf[0:2]))
			buf = buf[2:]
		} else {
			if len(buf) < 1 {
				return errors.New("attribute length truncated")
			}
			alen = int(buf[0])
			buf = buf[1:]
		}
		if alen > len(buf) {
			return fmt.Errorf("attribute %d length %d exceeds buffer %d", typ, alen, len(buf))
		}
		val := buf[:alen]
		buf = buf[alen:]
		switch typ {
		case bgpAttrOrigin:
			if alen >= 1 {
				u.Origin = val[0]
			}
		case bgpAttrASPath:
			path, err := parseASPath(val, 4)
			if err == nil {
				u.ASPath = path
			}
		case bgpAttrAS4Path:
			path, err := parseASPath(val, 4)
			if err == nil && len(path) > 0 && len(u.ASPath) == 0 {
				u.ASPath = path
			}
		case bgpAttrNextHop:
			if alen >= 4 {
				copy(u.NextHopV4[:], val[:4])
				u.HaveNextHopV4 = true
			}
		case bgpAttrMED:
			if alen >= 4 {
				u.MED = binary.BigEndian.Uint32(val[:4])
			}
		case bgpAttrLocalPref:
			if alen >= 4 {
				u.LocalPref = binary.BigEndian.Uint32(val[:4])
			}
		case bgpAttrMPReachNLRI:
			if err := parseMPReach(val, u); err != nil {
				return fmt.Errorf("MP_REACH: %w", err)
			}
		case bgpAttrMPUnreachNLRI:
			if err := parseMPUnreach(val, u); err != nil {
				return fmt.Errorf("MP_UNREACH: %w", err)
			}
		default:
			// Skip / opaque.
		}
	}
	return nil
}

// parseASPath supports 4-byte ASN segments (asnSize=4).
func parseASPath(buf []byte, asnSize int) ([]uint32, error) {
	var out []uint32
	for len(buf) > 0 {
		if len(buf) < 2 {
			return out, errors.New("as_path segment header truncated")
		}
		// segType := buf[0]
		segLen := int(buf[1])
		buf = buf[2:]
		need := segLen * asnSize
		if need > len(buf) {
			return out, fmt.Errorf("as_path segment %d ASNs need %d bytes, have %d", segLen, need, len(buf))
		}
		for i := 0; i < segLen; i++ {
			if asnSize == 4 {
				out = append(out, binary.BigEndian.Uint32(buf[i*4:i*4+4]))
			} else {
				out = append(out, uint32(binary.BigEndian.Uint16(buf[i*2:i*2+2])))
			}
		}
		buf = buf[need:]
	}
	return out, nil
}

func parseMPReach(buf []byte, u *bgpUpdate) error {
	if len(buf) < 5 {
		return errors.New("MP_REACH truncated")
	}
	afi := binary.BigEndian.Uint16(buf[0:2])
	safi := buf[2]
	nhLen := int(buf[3])
	if 4+nhLen+1 > len(buf) {
		return errors.New("MP_REACH next-hop truncated")
	}
	nhBytes := buf[4 : 4+nhLen]
	// 1 reserved byte after next hop.
	rest := buf[4+nhLen+1:]

	if afi == 2 && safi == 1 {
		if nhLen >= 16 {
			copy(u.NextHopV6[:], nhBytes[:16])
			u.HaveNextHopV6 = true
		}
		nlris, err := parseNLRI(rest, 6)
		if err != nil {
			return err
		}
		u.AnnouncedV6 = append(u.AnnouncedV6, nlris...)
		return nil
	}
	if afi == 1 && safi == 1 {
		if nhLen >= 4 {
			copy(u.NextHopV4[:], nhBytes[:4])
			u.HaveNextHopV4 = true
		}
		nlris, err := parseNLRI(rest, 4)
		if err != nil {
			return err
		}
		u.AnnouncedV4 = append(u.AnnouncedV4, nlris...)
		return nil
	}
	// Unknown AFI/SAFI in MVP — ignore but not an error.
	return nil
}

func parseMPUnreach(buf []byte, u *bgpUpdate) error {
	if len(buf) < 3 {
		return errors.New("MP_UNREACH truncated")
	}
	afi := binary.BigEndian.Uint16(buf[0:2])
	safi := buf[2]
	rest := buf[3:]
	if afi == 2 && safi == 1 {
		nlris, err := parseNLRI(rest, 6)
		if err != nil {
			return err
		}
		u.WithdrawnV6 = append(u.WithdrawnV6, nlris...)
		return nil
	}
	if afi == 1 && safi == 1 {
		nlris, err := parseNLRI(rest, 4)
		if err != nil {
			return err
		}
		u.WithdrawnV4 = append(u.WithdrawnV4, nlris...)
		return nil
	}
	return nil
}
