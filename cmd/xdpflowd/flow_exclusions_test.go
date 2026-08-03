package main

import (
	"testing"

	"xdpflowd/internal/flowingest"
)

func kvAddr4(a, b, c, d byte) [16]byte {
	var out [16]byte
	out[0], out[1], out[2], out[3] = a, b, c, d
	return out
}

func testExcluder(t *testing.T, specs ...flowingest.ExclusionRuleSpec) (*flowingest.ExclusionFilter, func([]flowKV) []flowKV) {
	t.Helper()
	f, rejected := flowingest.NewStaticExclusionFilter(specs)
	if len(rejected) > 0 {
		t.Fatalf("rules rejected by the loader: %v", rejected)
	}
	return f, newFlowKVExcluder(f, "xdp-test", [16]byte{})
}

func TestFlowKVExcluderDropsMatchingFlows(t *testing.T) {
	f, exclude := testExcluder(t, flowingest.ExclusionRuleSpec{
		RuleID: "r1", Prefix: "10.10.0.0/16", Family: 4, MatchSide: "any",
	})

	chunk := []flowKV{
		{k: FlowKey{SrcAddr: kvAddr4(10, 10, 0, 1), DstAddr: kvAddr4(8, 8, 8, 8), IPVersion: 4},
			v: FlowValue{Packets: 2, Bytes: 200}},
		{k: FlowKey{SrcAddr: kvAddr4(1, 1, 1, 1), DstAddr: kvAddr4(8, 8, 8, 8), IPVersion: 4},
			v: FlowValue{Packets: 3, Bytes: 300}},
	}
	kept := exclude(chunk)

	if len(kept) != 1 {
		t.Fatalf("kept %d flows, want 1", len(kept))
	}
	if kept[0].k.SrcAddr != kvAddr4(1, 1, 1, 1) {
		t.Fatalf("kept the wrong flow: %v", kept[0].k.SrcAddr)
	}
	if st := f.Stats(); st.Rows != 1 || st.Packets != 2 || st.Bytes != 200 {
		t.Fatalf("stats = %+v, want rows=1 packets=2 bytes=200", st)
	}
}

// The legacy drain paths delete the entries they handed to the callback, so the
// excluder must leave the original chunk untouched. Compacting it in place
// would silently leak excluded flows into the BPF map forever.
func TestFlowKVExcluderLeavesChunkIntactForDeletion(t *testing.T) {
	_, exclude := testExcluder(t, flowingest.ExclusionRuleSpec{
		RuleID: "r1", Prefix: "10.10.0.0/16", Family: 4, MatchSide: "any",
	})

	chunk := []flowKV{
		{k: FlowKey{SrcAddr: kvAddr4(10, 10, 0, 1), DstAddr: kvAddr4(8, 8, 8, 8), IPVersion: 4}},
		{k: FlowKey{SrcAddr: kvAddr4(1, 1, 1, 1), DstAddr: kvAddr4(8, 8, 8, 8), IPVersion: 4}},
		{k: FlowKey{SrcAddr: kvAddr4(10, 10, 0, 2), DstAddr: kvAddr4(8, 8, 8, 8), IPVersion: 4}},
	}
	before := append([]flowKV(nil), chunk...)

	if kept := exclude(chunk); len(kept) != 1 {
		t.Fatalf("kept %d flows, want 1", len(kept))
	}
	for i := range chunk {
		if chunk[i] != before[i] {
			t.Fatalf("chunk[%d] was mutated: %+v != %+v", i, chunk[i], before[i])
		}
	}
}

// Nothing matched means no copy: the hot path has to hand the original slice
// straight through.
func TestFlowKVExcluderReturnsSameSliceWhenNothingMatches(t *testing.T) {
	_, exclude := testExcluder(t, flowingest.ExclusionRuleSpec{
		RuleID: "r1", Prefix: "10.10.0.0/16", Family: 4, MatchSide: "any",
	})

	chunk := []flowKV{
		{k: FlowKey{SrcAddr: kvAddr4(1, 1, 1, 1), DstAddr: kvAddr4(8, 8, 8, 8), IPVersion: 4}},
	}
	kept := exclude(chunk)
	if len(kept) != 1 || &kept[0] != &chunk[0] {
		t.Fatal("a chunk with no matches must be returned as-is")
	}
}

// BPF stores ports in network byte order; the rule catalog is in host order.
// keyPortHost is a plain byte swap, so applying it to 53 yields the value the
// BPF map would hold for that port.
func TestFlowKVExcluderConvertsPortByteOrder(t *testing.T) {
	_, exclude := testExcluder(t, flowingest.ExclusionRuleSpec{
		RuleID: "r1", Proto: 17, PortFrom: 53, PortTo: 53, PortSide: "dst",
	})

	chunk := []flowKV{
		{k: FlowKey{SrcAddr: kvAddr4(1, 1, 1, 1), DstAddr: kvAddr4(8, 8, 8, 8),
			IPVersion: 4, Proto: 17, DstPort: keyPortHost(53)}},
	}
	if kept := exclude(chunk); len(kept) != 0 {
		t.Fatal("UDP/53 must be dropped by a dst-port rule")
	}
}

func TestNilFilterInstallsNoExcluder(t *testing.T) {
	if newFlowKVExcluder(nil, "xdp-test", [16]byte{}) != nil {
		t.Fatal("a nil filter must not install a drainer hook")
	}
}
