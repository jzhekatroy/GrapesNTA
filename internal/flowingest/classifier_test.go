package flowingest

import (
	"net/netip"
	"testing"
)

func TestDeriveDirection(t *testing.T) {
	cases := []struct {
		name string
		src  EndpointClass
		dst  EndpointClass
		want string
	}{
		{
			name: "provider to remote is out",
			src:  EndpointClass{Role: "provider_public"},
			dst:  EndpointClass{Role: "remote"},
			want: "out",
		},
		{
			name: "remote to customer allocated is in",
			src:  EndpointClass{Role: "remote"},
			dst:  EndpointClass{Role: "customer_allocated"},
			want: "in",
		},
		{
			name: "internal to customer transit is internal",
			src:  EndpointClass{Role: "internal"},
			dst:  EndpointClass{Role: "customer_transit"},
			want: "internal",
		},
		{
			name: "remote to remote is transit",
			src:  EndpointClass{Role: "remote"},
			dst:  EndpointClass{Role: "remote"},
			want: "transit",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveDirection(true, tc.src, tc.dst)
			if got != tc.want {
				t.Fatalf("DeriveDirection() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeriveDirectionNoConfig(t *testing.T) {
	got := DeriveDirection(false, EndpointClass{Role: "internal"}, EndpointClass{Role: "remote"})
	if got != "unknown" {
		t.Fatalf("DeriveDirection() = %q, want unknown", got)
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
	direction := DeriveDirection(st.hasLocalConfig, src, dst)
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
