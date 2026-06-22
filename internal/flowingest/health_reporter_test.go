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
