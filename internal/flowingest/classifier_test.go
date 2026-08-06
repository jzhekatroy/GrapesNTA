package flowingest

import (
	"net/netip"
	"testing"
)

func TestDeriveDirection(t *testing.T) {
	cases := []struct {
		name            string
		src             EndpointClass
		dst             EndpointClass
		unknownNetworks string
		want            string
	}{
		{
			name:            "provider to remote is out",
			src:             EndpointClass{Role: "provider_public"},
			dst:             EndpointClass{Role: "remote"},
			unknownNetworks: UnknownNetworksForeign,
			want:            "out",
		},
		{
			name:            "remote to customer allocated is in",
			src:             EndpointClass{Role: "remote"},
			dst:             EndpointClass{Role: "customer_allocated"},
			unknownNetworks: UnknownNetworksForeign,
			want:            "in",
		},
		{
			name:            "internal to customer transit is internal",
			src:             EndpointClass{Role: "internal"},
			dst:             EndpointClass{Role: "customer_transit"},
			unknownNetworks: UnknownNetworksForeign,
			want:            "internal",
		},
		{
			name:            "remote to remote is transit",
			src:             EndpointClass{Role: "remote"},
			dst:             EndpointClass{Role: "remote"},
			unknownNetworks: UnknownNetworksForeign,
			want:            "transit",
		},
		{
			// One end is ours, so the direction holds no matter what the other
			// end is: foreign networks never need markup for in/out.
			name:            "local to undescribed stays out when strict",
			src:             EndpointClass{Role: "provider_public", Source: endpointSourcePrefix},
			dst:             EndpointClass{Role: "remote", Source: "fallback"},
			unknownNetworks: UnknownNetworksUnclassified,
			want:            "out",
		},
		{
			name:            "two catalogued foreign networks are transit when strict",
			src:             EndpointClass{Role: "remote", Source: endpointSourcePrefix},
			dst:             EndpointClass{Role: "remote", Source: endpointSourcePrefix},
			unknownNetworks: UnknownNetworksUnclassified,
			want:            "transit",
		},
		{
			name:            "one undescribed end is not transit when strict",
			src:             EndpointClass{Role: "remote", Source: endpointSourcePrefix},
			dst:             EndpointClass{Role: "remote", Source: "fallback"},
			unknownNetworks: UnknownNetworksUnclassified,
			want:            DirectionUnknown,
		},
		{
			name:            "two undescribed ends are unclassified when strict",
			src:             EndpointClass{Role: "remote", Source: "fallback"},
			dst:             EndpointClass{Role: "remote", Source: "fallback"},
			unknownNetworks: UnknownNetworksUnclassified,
			want:            DirectionUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveDirection(tc.src, tc.dst, tc.unknownNetworks)
			if got != tc.want {
				t.Fatalf("DeriveDirection() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeriveDirectionEmptyCatalogKeepsTransitByDefault(t *testing.T) {
	// Empty L3 catalog → classify() yields remote/remote. Installations that
	// never touched the setting must not see their traffic move categories.
	got := DeriveDirection(
		EndpointClass{Role: "remote", Source: "fallback"},
		EndpointClass{Role: "remote", Source: "fallback"},
		UnknownNetworksForeign,
	)
	if got != "transit" {
		t.Fatalf("DeriveDirection() = %q, want transit", got)
	}
}

func TestClassifyLocalPrefixOriginASNWithoutBGP(t *testing.T) {
	st := &classifierState{
		l3v4: newIPTrie(),
		bgp4: newIPTrie(),
	}
	prefix := netip.MustParsePrefix("188.143.128.0/17")
	st.l3v4.Insert(prefix.Masked(), prefixClass{
		ASN:         34665,
		Role:        "provider_public",
		EntityID:    "isp:pin",
		DisplayName: "gb",
	})

	got := st.classify(netip.MustParseAddr("188.143.128.236"), 0)
	if got.ASN != 34665 {
		t.Fatalf("classify().ASN = %d, want 34665", got.ASN)
	}
	if got.Role != "provider_public" {
		t.Fatalf("classify().Role = %q, want provider_public", got.Role)
	}
	if got.Scope != "local" {
		t.Fatalf("classify().Scope = %q, want local", got.Scope)
	}
}

func TestClassifyLocalPrefixFallsBackToBGPWhenOriginASNZero(t *testing.T) {
	st := &classifierState{
		l3v4: newIPTrie(),
		bgp4: newIPTrie(),
	}
	prefix := netip.MustParsePrefix("188.143.128.0/17")
	st.l3v4.Insert(prefix.Masked(), prefixClass{
		Role:        "provider_public",
		EntityID:    "isp:pin",
		DisplayName: "gb",
	})
	st.bgp4.Insert(prefix.Masked(), prefixClass{ASN: 12345})

	got := st.classify(netip.MustParseAddr("188.143.128.236"), 0)
	if got.ASN != 12345 {
		t.Fatalf("classify().ASN = %d, want 12345", got.ASN)
	}
}

func TestClassifyRemoteUsesBGP(t *testing.T) {
	st := &classifierState{
		l3v4: newIPTrie(),
		bgp4: newIPTrie(),
	}
	st.bgp4.Insert(netip.MustParsePrefix("8.8.8.0/24"), prefixClass{ASN: 15169})

	got := st.classify(netip.MustParseAddr("8.8.8.8"), 0)
	if got.ASN != 15169 {
		t.Fatalf("classify().ASN = %d, want 15169", got.ASN)
	}
	if got.Role != "remote" {
		t.Fatalf("classify().Role = %q, want remote", got.Role)
	}
}

func TestClassifyRemoteUsesIPASNFallback(t *testing.T) {
	st := &classifierState{
		bgp4: newIPTrie(),
		asn4: newIPTrie(),
		l3v4: newIPTrie(),
	}
	st.asn4.Insert(netip.MustParsePrefix("8.8.8.0/24"), prefixClass{ASN: 15169})

	got := st.classify(netip.MustParseAddr("8.8.8.8"), 0)
	if got.ASN != 15169 {
		t.Fatalf("classify().ASN = %d, want 15169", got.ASN)
	}
	if got.Role != "remote" {
		t.Fatalf("classify().Role = %q, want remote", got.Role)
	}
}

func TestClassifyBGPOverridesIPASNFallback(t *testing.T) {
	st := &classifierState{
		bgp4: newIPTrie(),
		asn4: newIPTrie(),
		l3v4: newIPTrie(),
	}
	st.asn4.Insert(netip.MustParsePrefix("8.8.8.0/24"), prefixClass{ASN: 64512})
	st.bgp4.Insert(netip.MustParsePrefix("8.8.8.0/24"), prefixClass{ASN: 15169})

	got := st.classify(netip.MustParseAddr("8.8.8.8"), 0)
	if got.ASN != 15169 {
		t.Fatalf("classify().ASN = %d, want BGP ASN 15169", got.ASN)
	}
}

func TestClassifyLocalOriginASNOverridesIPASNFallback(t *testing.T) {
	st := &classifierState{
		asn4: newIPTrie(),
		l3v4: newIPTrie(),
	}
	st.asn4.Insert(netip.MustParsePrefix("188.143.128.0/17"), prefixClass{ASN: 64512})
	st.l3v4.Insert(netip.MustParsePrefix("188.143.128.0/17"), prefixClass{
		ASN:         34665,
		Role:        "provider_public",
		EntityID:    "isp:pin",
		DisplayName: "gb",
	})

	got := st.classify(netip.MustParseAddr("188.143.128.236"), 0)
	if got.ASN != 34665 {
		t.Fatalf("classify().ASN = %d, want local origin ASN 34665", got.ASN)
	}
}

func TestClassifyPairOutboundUsesLocalOriginASN(t *testing.T) {
	st := &classifierState{
		l3v4:           newIPTrie(),
		bgp4:           newIPTrie(),
		hasLocalConfig: true,
	}
	localPrefix := netip.MustParsePrefix("188.143.128.0/17")
	st.l3v4.Insert(localPrefix.Masked(), prefixClass{
		ASN:         34665,
		Role:        "provider_public",
		EntityID:    "isp:pin",
		DisplayName: "gb",
	})
	st.bgp4.Insert(netip.MustParsePrefix("142.250.0.0/15"), prefixClass{ASN: 15169})

	src := st.classify(netip.MustParseAddr("188.143.128.236"), 0)
	dst := st.classify(netip.MustParseAddr("142.250.74.46"), 0)
	direction := DeriveDirection(src, dst, UnknownNetworksForeign)
	if direction != "out" {
		t.Fatalf("direction = %q, want out", direction)
	}
	if src.ASN != 34665 {
		t.Fatalf("src.ASN = %d, want 34665", src.ASN)
	}
	if dst.ASN != 15169 {
		t.Fatalf("dst.ASN = %d, want 15169", dst.ASN)
	}
}

func portModeClassifier(t *testing.T, sampler [16]byte) *TrafficClassifier {
	t.Helper()
	tc := &TrafficClassifier{}
	tc.state.Store(&classifierState{
		directionMode: DirectionModePorts,
		portSides: map[portKey]uint8{
			{sampler: sampler, ifIndex: 10}: portSideInternal,
			{sampler: sampler, ifIndex: 20}: portSideExternal,
		},
	})
	return tc
}

func TestPortDirectionPairs(t *testing.T) {
	sampler, err := ParseSamplerAddress("172.18.19.110")
	if err != nil {
		t.Fatalf("ParseSamplerAddress: %v", err)
	}
	other, err := ParseSamplerAddress("172.18.19.111")
	if err != nil {
		t.Fatalf("ParseSamplerAddress: %v", err)
	}
	cases := []struct {
		name    string
		sampler [16]byte
		inIf    uint32
		outIf   uint32
		want    string
	}{
		{name: "external to internal is in", sampler: sampler, inIf: 20, outIf: 10, want: "in"},
		{name: "internal to external is out", sampler: sampler, inIf: 10, outIf: 20, want: "out"},
		{name: "internal to internal", sampler: sampler, inIf: 10, outIf: 10, want: "internal"},
		{name: "external to external is transit", sampler: sampler, inIf: 20, outIf: 20, want: "transit"},
		{name: "unmarked port is unknown", sampler: sampler, inIf: 10, outIf: 99, want: "unknown"},
		{name: "missing ifindex is unknown", sampler: sampler, inIf: 0, outIf: 10, want: "unknown"},
		{name: "another switch is unknown", sampler: other, inIf: 20, outIf: 10, want: "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := portModeClassifier(t, sampler)
			got, ok := c.PortDirection(tc.sampler, tc.inIf, tc.outIf)
			if !ok {
				t.Fatal("PortDirection() reported prefix mode, want port mode")
			}
			if got != tc.want {
				t.Fatalf("PortDirection() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPortDirectionCounters(t *testing.T) {
	sampler, err := ParseSamplerAddress("172.18.19.110")
	if err != nil {
		t.Fatalf("ParseSamplerAddress: %v", err)
	}
	c := portModeClassifier(t, sampler)
	c.PortDirection(sampler, 20, 10)
	c.PortDirection(sampler, 10, 99)
	c.PortDirection(sampler, 0, 0)
	if got := c.portsClassified.Load(); got != 1 {
		t.Fatalf("portsClassified = %d, want 1", got)
	}
	if got := c.portsUnmarked.Load(); got != 1 {
		t.Fatalf("portsUnmarked = %d, want 1", got)
	}
	if got := c.portsNoIfIndex.Load(); got != 1 {
		t.Fatalf("portsNoIfIndex = %d, want 1", got)
	}
}

func TestPortDirectionIgnoredInPrefixMode(t *testing.T) {
	sampler, err := ParseSamplerAddress("172.18.19.110")
	if err != nil {
		t.Fatalf("ParseSamplerAddress: %v", err)
	}
	tc := &TrafficClassifier{}
	tc.state.Store(&classifierState{
		directionMode: DirectionModePrefixes,
		portSides: map[portKey]uint8{
			{sampler: sampler, ifIndex: 10}: portSideInternal,
			{sampler: sampler, ifIndex: 20}: portSideExternal,
		},
	})
	if _, ok := tc.PortDirection(sampler, 20, 10); ok {
		t.Fatal("PortDirection() applied port sides in prefix mode")
	}
	if got := tc.DirectionMode(); got != DirectionModePrefixes {
		t.Fatalf("DirectionMode() = %q, want %q", got, DirectionModePrefixes)
	}
}

func TestDirectionModeDefaultsToPrefixes(t *testing.T) {
	var nilClassifier *TrafficClassifier
	if got := nilClassifier.DirectionMode(); got != DirectionModePrefixes {
		t.Fatalf("nil DirectionMode() = %q, want %q", got, DirectionModePrefixes)
	}
	if _, ok := nilClassifier.PortDirection([16]byte{}, 10, 20); ok {
		t.Fatal("nil PortDirection() must not claim port mode")
	}
	empty := &TrafficClassifier{}
	if got := empty.DirectionMode(); got != DirectionModePrefixes {
		t.Fatalf("unloaded DirectionMode() = %q, want %q", got, DirectionModePrefixes)
	}
	if _, ok := empty.PortDirection([16]byte{}, 10, 20); ok {
		t.Fatal("unloaded PortDirection() must not claim port mode")
	}
}

func TestPortSideKeyMatchesSFlowSamplerEncoding(t *testing.T) {
	// The catalog stores switch_ip as text while flows carry a 16-byte sampler
	// address with IPv4 in the first four bytes. Both must produce one key.
	sampler, err := ParseSamplerAddress("172.18.19.110")
	if err != nil {
		t.Fatalf("ParseSamplerAddress: %v", err)
	}
	want := [16]byte{172, 18, 19, 110}
	if sampler != want {
		t.Fatalf("sampler = %v, want %v", sampler, want)
	}
}
