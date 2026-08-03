package flowingest

import (
	"strings"
	"testing"
)

// Captured from /proc/net/udp on the m61 collector: nfcapd on 9996 (0x270C)
// and the second nfcapd on 2055 (0x0807).
const procNetUDPSample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 3084: 00000000:270C 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 41283 2 ffff9a1c0a1b0000 5205
 3085: 00000000:0807 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 41291 2 ffff9a1c0a1b8000 454519
 3086: 0100007F:90CB 0100007F:270C 01 00000000:00000000 00:00000000 00000000     0        0 41310 2 ffff9a1c0a1c0000 0
`

func TestParseUDPDropsFindsBoundSocket(t *testing.T) {
	drops, found := parseUDPDrops(strings.NewReader(procNetUDPSample), 9996)
	if !found {
		t.Fatal("socket on port 9996 not found")
	}
	if drops != 5205 {
		t.Fatalf("drops = %d, want 5205", drops)
	}
}

func TestParseUDPDropsSecondInstance(t *testing.T) {
	drops, found := parseUDPDrops(strings.NewReader(procNetUDPSample), 2055)
	if !found || drops != 454519 {
		t.Fatalf("port 2055: drops=%d found=%v, want 454519 true", drops, found)
	}
}

// A missing socket must not read as "zero drops": the caller reports the leg as
// unobserved instead of healthy.
func TestParseUDPDropsMissingSocket(t *testing.T) {
	drops, found := parseUDPDrops(strings.NewReader(procNetUDPSample), 4739)
	if found {
		t.Fatalf("port 4739 reported as present with drops=%d", drops)
	}
}

// The ephemeral source port of an established socket shares the file; matching
// must key on the local port only.
func TestParseUDPDropsMatchesLocalPortOnly(t *testing.T) {
	_, found := parseUDPDrops(strings.NewReader(procNetUDPSample), 0x90CB)
	if !found {
		t.Fatal("local port 0x90CB not matched")
	}
}

func TestParseUDPDropsIgnoresHeader(t *testing.T) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	if _, found := parseUDPDrops(strings.NewReader(header), 9996); found {
		t.Fatal("header line parsed as a socket")
	}
}

func TestLocalSinkPortsKeepsLoopbackDropsRemote(t *testing.T) {
	ports := LocalSinkPorts([]string{"127.0.0.1:9996", "10.99.99.99:2055", "127.0.0.1:9996"})
	if len(ports) != 1 || ports[0] != 9996 {
		t.Fatalf("ports = %v, want [9996]", ports)
	}
}

func TestLocalSinkPortsIgnoresGarbage(t *testing.T) {
	if got := LocalSinkPorts([]string{"", "nope", "127.0.0.1", "127.0.0.1:0"}); len(got) != 0 {
		t.Fatalf("ports = %v, want empty", got)
	}
}
