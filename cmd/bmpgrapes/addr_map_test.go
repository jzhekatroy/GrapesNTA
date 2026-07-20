package main

import (
	"net"
	"testing"
)

func TestParseRouterAddrMap(t *testing.T) {
	m, err := parseRouterAddrMap(`
		5.188.236.252=10.70.0.55 # m9.mx304-1,
		5.188.236.250=10.70.0.77,
		5.188.236.251=10.70.0.80
	`)
	if err != nil {
		t.Fatal(err)
	}
	if got := m[ipMapKey(net.ParseIP("5.188.236.252"))].String(); got != "10.70.0.55" {
		t.Fatalf("252 -> %s", got)
	}
	if got := resolveRouterAddr(net.ParseIP("5.188.236.250"), m).String(); got != "10.70.0.77" {
		t.Fatalf("resolve 250 -> %s", got)
	}
	if got := resolveRouterAddr(net.ParseIP("1.2.3.4"), m).String(); got != "1.2.3.4" {
		t.Fatalf("unmapped passthrough -> %s", got)
	}
}

func TestParseRouterAddrMapInvalid(t *testing.T) {
	if _, err := parseRouterAddrMap("not-an-entry"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := parseRouterAddrMap("5.188.236.252=nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRouterAddrBytesIPv4(t *testing.T) {
	b := routerAddrBytes(net.ParseIP("10.70.0.55"))
	ip := net.IP(b[:])
	if got := ip.To4().String(); got != "10.70.0.55" {
		t.Fatalf("got %s", got)
	}
}
