package flowingest

import (
	"testing"
	"time"
)

func TestClassifyHealthStatusOK(t *testing.T) {
	status, reasons := classifyHealthStatus(HealthWriteInput{})
	if status != "ok" || len(reasons) != 0 {
		t.Fatalf("status=%q reasons=%v", status, reasons)
	}
}

func TestClassifyHealthStatusCriticalMapFull(t *testing.T) {
	status, reasons := classifyHealthStatus(HealthWriteInput{MapFullDelta: 1})
	if status != "critical" || len(reasons) != 1 || reasons[0] != "xdp_map_full" {
		t.Fatalf("status=%q reasons=%v", status, reasons)
	}
}

func TestClassifyPhyDiscards(t *testing.T) {
	// The steady rate measured on m61 at 2.5 Mpps: real loss, but two orders
	// of magnitude below anything worth waking someone for.
	cases := []struct {
		name     string
		packets  uint64
		discards uint64
		want     string
	}{
		{"clean", 154958093, 0, ""},
		{"m61 steady state", 154958093, 6324, ""},
		{"above warn", 1000000, 200, "warning"},
		{"above critical", 1000000, 2000, "critical"},
		{"no denominator", 0, 1, "warning"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := HealthWriteInput{PhyRxPacketDelta: tc.packets, PhyRxDiscardDelta: tc.discards}
			level, ok := classifyPhyDiscards(in)
			if tc.want == "" {
				if ok {
					t.Fatalf("expected silence, got %q", level)
				}
				return
			}
			if !ok || level != tc.want {
				t.Fatalf("got %q (ok=%v), want %q", level, ok, tc.want)
			}
		})
	}
}

func TestClassifyHealthStatusWarningLag(t *testing.T) {
	status, reasons := classifyHealthStatus(HealthWriteInput{
		CH: HealthSnapshot{
			LagSegments:        20,
			DrainerProgressAge: 3 * time.Minute,
		},
		LagSegmentsThreshold: 10,
		DrainerAgeThreshold:  2 * time.Minute,
	})
	if status != "warning" {
		t.Fatalf("status=%q reasons=%v", status, reasons)
	}
}
