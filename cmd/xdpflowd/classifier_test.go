package main

import (
	"testing"
)

func TestDeriveDirection(t *testing.T) {
	cases := []struct {
		name string
		src  endpointClass
		dst  endpointClass
		want string
	}{
		{
			name: "provider to remote is out",
			src:  endpointClass{Role: "provider_public"},
			dst:  endpointClass{Role: "remote"},
			want: "out",
		},
		{
			name: "remote to customer allocated is in",
			src:  endpointClass{Role: "remote"},
			dst:  endpointClass{Role: "customer_allocated"},
			want: "in",
		},
		{
			name: "internal to customer transit is internal",
			src:  endpointClass{Role: "internal"},
			dst:  endpointClass{Role: "customer_transit"},
			want: "internal",
		},
		{
			name: "remote to remote is transit",
			src:  endpointClass{Role: "remote"},
			dst:  endpointClass{Role: "remote"},
			want: "transit",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveDirection(true, tc.src, tc.dst)
			if got != tc.want {
				t.Fatalf("deriveDirection() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeriveDirectionNoConfig(t *testing.T) {
	got := deriveDirection(false, endpointClass{Role: "internal"}, endpointClass{Role: "remote"})
	if got != "unknown" {
		t.Fatalf("deriveDirection(no config) = %q, want unknown", got)
	}
}

func TestNormalizeRole(t *testing.T) {
	if got := normalizeRole(" Customer_Allocated "); got != "customer_allocated" {
		t.Fatalf("normalizeRole() = %q", got)
	}
	if got := normalizeRole(""); got != "remote" {
		t.Fatalf("normalizeRole(empty) = %q", got)
	}
}

func TestScopeFromRole(t *testing.T) {
	if got := scopeFromRole("provider_public"); got != "local" {
		t.Fatalf("scopeFromRole(provider_public) = %q", got)
	}
	if got := scopeFromRole("customer_transit"); got != "customer" {
		t.Fatalf("scopeFromRole(customer_transit) = %q", got)
	}
}
