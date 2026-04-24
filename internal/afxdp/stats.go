package afxdp

import (
	"encoding/json"
	"sync/atomic"
)

// Stats is updated from the XDP/AF_XDP receive path (one writer goroutine; atomics for reads).
type Stats struct {
	packets, bytes              atomic.Uint64
	ipv4, ipv6, other, tooShort atomic.Uint64
	parseErr, nonIP, mapFull    atomic.Uint64
	pollIters                   atomic.Uint64
}

func (s *Stats) AddPoll() {
	s.pollIters.Add(1)
}

func (s *Stats) addFrame(nbytes int, class classifyResult) {
	s.packets.Add(1)
	s.bytes.Add(uint64(nbytes))
	if class.tooShort {
		s.tooShort.Add(1)
		return
	}
	switch class.l3 {
	case l3IPv4:
		s.ipv4.Add(1)
	case l3IPv6:
		s.ipv6.Add(1)
	default:
		s.other.Add(1)
	}
}

// WireGroundTruth is emitted as JSON for comparison with NetFlow and sysfs/ethtool.
type WireGroundTruth struct {
	Packets        uint64 `json:"packets"`
	Bytes          uint64 `json:"bytes"`
	IPv4           uint64 `json:"ipv4"`
	IPv6           uint64 `json:"ipv6"`
	Other          uint64 `json:"other"`
	TooShort       uint64 `json:"too_short"`
	ParseErrors    uint64 `json:"parse_errors,omitempty"`
	NonIP          uint64 `json:"non_ip_pass,omitempty"`
	MapFull        uint64 `json:"map_full,omitempty"`
	PollIterations uint64 `json:"poll_iterations"`
}

// snapshot returns current counters.
func (s *Stats) snapshot() WireGroundTruth {
	return WireGroundTruth{
		Packets:        s.packets.Load(),
		Bytes:          s.bytes.Load(),
		IPv4:           s.ipv4.Load(),
		IPv6:           s.ipv6.Load(),
		Other:          s.other.Load(),
		TooShort:       s.tooShort.Load(),
		ParseErrors:    s.parseErr.Load(),
		NonIP:          s.nonIP.Load(),
		MapFull:        s.mapFull.Load(),
		PollIterations: s.pollIters.Load(),
	}
}

// MarshalJSONLine returns a single JSON object with newline.
func (s *Stats) MarshalJSONLine() ([]byte, error) {
	m := struct {
		WireGroundTruth WireGroundTruth `json:"wire_ground_truth"`
	}{WireGroundTruth: s.snapshot()}
	return json.Marshal(m)
}
