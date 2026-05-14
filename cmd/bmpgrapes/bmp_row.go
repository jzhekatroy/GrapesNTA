package main

import "time"

// PeerRow matches default.bmp_peers (state events).
type PeerRow struct {
	Ts          time.Time
	RouterAddr  [16]byte
	PeerAddr    [16]byte
	PeerASN     uint32
	PeerType    uint8 // BMP per-peer header peer type (0=global, 1=RD, 2=local)
	IsIPv6      uint8
	State       string // "up" or "down"
	Reason      string // peer down reason or empty
	LocalASN    uint32 // for peer up: local AS
	LocalAddr   [16]byte
	HoldTime    uint16
	NegotiatedHoldTime uint16
	BGPID       uint32 // peer BGP ID as uint32 (IPv4-form)
}

// RouteEventRow matches default.bmp_route_events.
type RouteEventRow struct {
	Ts         time.Time
	RouterAddr [16]byte
	PeerAddr   [16]byte
	PeerASN    uint32
	EventType  string // "announce" or "withdraw"
	Family     uint8  // 4 = IPv4 unicast, 6 = IPv6 unicast
	Prefix     [16]byte
	PrefixLen  uint8
	NextHop    [16]byte
	OriginASN  uint32
	ASPath     []uint32
	MED        uint32
	LocalPref  uint32
}
