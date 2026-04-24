package afxdp

// Ethernet + optional 802.1Q / QinQ; counts L2 frame length for byte totals.

const (
	ethtypeIPv4  = 0x0800
	ethtypeIPv6  = 0x86dd
	ethtypeVLAN  = 0x8100
	ethtypeQinQ  = 0x88a8
	minEthHeader = 14
)

type l3Kind int

const (
	l3Other l3Kind = iota
	l3IPv4
	l3IPv6
)

type classifyResult struct {
	l3       l3Kind
	tooShort bool
}

func classifyL2(frame []byte) classifyResult {
	if len(frame) < minEthHeader {
		return classifyResult{tooShort: true}
	}
	off := 12
	et := uint16(frame[off])<<8 | uint16(frame[off+1])
	off = 14
	for et == ethtypeVLAN || et == ethtypeQinQ {
		if len(frame) < off+4 {
			return classifyResult{tooShort: true}
		}
		et = uint16(frame[off+2])<<8 | uint16(frame[off+3])
		off += 4
	}
	switch et {
	case ethtypeIPv4:
		return classifyResult{l3: l3IPv4}
	case ethtypeIPv6:
		return classifyResult{l3: l3IPv6}
	default:
		return classifyResult{l3: l3Other}
	}
}
