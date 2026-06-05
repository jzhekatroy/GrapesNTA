package flowingest

import "testing"

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
