package flowingest

import (
	"net/netip"
	"testing"
)

func newTestFilter(t *testing.T, specs ...ExclusionRuleSpec) *ExclusionFilter {
	t.Helper()
	f, rejected := NewStaticExclusionFilter(specs)
	if len(rejected) > 0 {
		t.Fatalf("rules rejected by the loader: %v", rejected)
	}
	return f
}

func v4(t *testing.T, s string) [16]byte {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	a4 := addr.As4()
	var out [16]byte
	copy(out[:4], a4[:])
	return out
}

func v6(t *testing.T, s string) [16]byte {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return addr.As16()
}

func rule(id, prefix string, family uint8, side string, proto uint8,
	portFrom, portTo uint16, portSide string, vlan uint16, switchIP string,
	ifIndex uint32, sourceID string) ExclusionRuleSpec {
	return ExclusionRuleSpec{
		RuleID: id, Prefix: prefix, Family: family, MatchSide: side, Proto: proto,
		PortFrom: portFrom, PortTo: portTo, PortSide: portSide, VLANID: vlan,
		SwitchIP: switchIP, IfIndex: ifIndex, SourceID: sourceID,
	}
}

func TestExclusionPrefixEitherSide(t *testing.T) {
	f := newTestFilter(t, rule("r1", "10.10.0.0/16", 4, "any", 0, 0, 0, "any", 0, "", 0, ""))

	inside := ExclusionMatch{SrcAddr: v4(t, "10.10.1.1"), DstAddr: v4(t, "8.8.8.8"), IPVersion: 4}
	if !f.Excluded(&inside) {
		t.Fatal("src inside the prefix must be excluded")
	}
	reversed := ExclusionMatch{SrcAddr: v4(t, "8.8.8.8"), DstAddr: v4(t, "10.10.1.1"), IPVersion: 4}
	if !f.Excluded(&reversed) {
		t.Fatal("dst inside the prefix must be excluded")
	}
	outside := ExclusionMatch{SrcAddr: v4(t, "10.11.1.1"), DstAddr: v4(t, "8.8.8.8"), IPVersion: 4}
	if f.Excluded(&outside) {
		t.Fatal("address outside the prefix must be kept")
	}
}

func TestExclusionMatchSideIsHonoured(t *testing.T) {
	f := newTestFilter(t, rule("r1", "10.10.0.0/16", 4, "src", 0, 0, 0, "any", 0, "", 0, ""))

	asSrc := ExclusionMatch{SrcAddr: v4(t, "10.10.1.1"), DstAddr: v4(t, "8.8.8.8"), IPVersion: 4}
	if !f.Excluded(&asSrc) {
		t.Fatal("match_side=src must drop the flow when src is inside")
	}
	asDst := ExclusionMatch{SrcAddr: v4(t, "8.8.8.8"), DstAddr: v4(t, "10.10.1.1"), IPVersion: 4}
	if f.Excluded(&asDst) {
		t.Fatal("match_side=src must keep the flow when only dst is inside")
	}
}

func TestExclusionPrefixAndPortAreANDed(t *testing.T) {
	f := newTestFilter(t, rule("r1", "10.10.0.0/16", 4, "any", 0, 53, 53, "dst", 0, "", 0, ""))

	hit := ExclusionMatch{SrcAddr: v4(t, "10.10.1.1"), DstAddr: v4(t, "8.8.8.8"), IPVersion: 4, DstPort: 53}
	if !f.Excluded(&hit) {
		t.Fatal("prefix and port both match: flow must be dropped")
	}
	wrongPort := ExclusionMatch{SrcAddr: v4(t, "10.10.1.1"), DstAddr: v4(t, "8.8.8.8"), IPVersion: 4, DstPort: 443}
	if f.Excluded(&wrongPort) {
		t.Fatal("prefix alone must not drop the flow when the rule also names a port")
	}
	wrongSide := ExclusionMatch{SrcAddr: v4(t, "10.10.1.1"), DstAddr: v4(t, "8.8.8.8"), IPVersion: 4, SrcPort: 53}
	if f.Excluded(&wrongSide) {
		t.Fatal("port_side=dst must not match a source port")
	}
}

// Overlapping prefixes carry independent conditions, so the wider rule has to
// be evaluated even when a more specific one exists.
func TestExclusionEvaluatesAllOverlappingPrefixes(t *testing.T) {
	f := newTestFilter(t,
		rule("wide", "10.0.0.0/8", 4, "any", 17, 0, 0, "any", 0, "", 0, ""),
		rule("narrow", "10.10.0.0/16", 4, "any", 6, 0, 0, "any", 0, "", 0, ""),
	)

	udp := ExclusionMatch{SrcAddr: v4(t, "10.10.1.1"), DstAddr: v4(t, "8.8.8.8"), IPVersion: 4, Proto: 17}
	if !f.Excluded(&udp) {
		t.Fatal("the wider /8 rule must still match an address covered by the /16")
	}
	tcp := ExclusionMatch{SrcAddr: v4(t, "10.10.1.1"), DstAddr: v4(t, "8.8.8.8"), IPVersion: 4, Proto: 6}
	if !f.Excluded(&tcp) {
		t.Fatal("the narrow /16 rule must match its own protocol")
	}
	icmp := ExclusionMatch{SrcAddr: v4(t, "10.10.1.1"), DstAddr: v4(t, "8.8.8.8"), IPVersion: 4, Proto: 1}
	if f.Excluded(&icmp) {
		t.Fatal("no rule covers ICMP: flow must be kept")
	}
}

func TestExclusionPortRange(t *testing.T) {
	f := newTestFilter(t, rule("r1", "", 0, "any", 6, 30000, 30010, "any", 0, "", 0, ""))

	for _, port := range []uint16{30000, 30005, 30010} {
		m := ExclusionMatch{SrcAddr: v4(t, "1.1.1.1"), DstAddr: v4(t, "2.2.2.2"), IPVersion: 4, Proto: 6, DstPort: port}
		if !f.Excluded(&m) {
			t.Fatalf("port %d is inside the range and must be dropped", port)
		}
	}
	outside := ExclusionMatch{SrcAddr: v4(t, "1.1.1.1"), DstAddr: v4(t, "2.2.2.2"), IPVersion: 4, Proto: 6, DstPort: 30011}
	if f.Excluded(&outside) {
		t.Fatal("port above the range must be kept")
	}
	wrongProto := ExclusionMatch{SrcAddr: v4(t, "1.1.1.1"), DstAddr: v4(t, "2.2.2.2"), IPVersion: 4, Proto: 17, DstPort: 30005}
	if f.Excluded(&wrongProto) {
		t.Fatal("protocol condition must still apply to a prefix-less rule")
	}
}

func TestExclusionSwitchPort(t *testing.T) {
	f := newTestFilter(t, rule("r1", "", 0, "any", 0, 0, 0, "any", 0, "192.0.2.7", 42, ""))

	sampler, err := ParseSamplerAddress("192.0.2.7")
	if err != nil {
		t.Fatalf("parse sampler: %v", err)
	}
	other, err := ParseSamplerAddress("192.0.2.8")
	if err != nil {
		t.Fatalf("parse sampler: %v", err)
	}

	ingress := ExclusionMatch{SrcAddr: v4(t, "1.1.1.1"), DstAddr: v4(t, "2.2.2.2"), IPVersion: 4, Sampler: sampler, InIf: 42}
	if !f.Excluded(&ingress) {
		t.Fatal("ifIndex on the named switch must be dropped")
	}
	egress := ExclusionMatch{SrcAddr: v4(t, "1.1.1.1"), DstAddr: v4(t, "2.2.2.2"), IPVersion: 4, Sampler: sampler, OutIf: 42}
	if !f.Excluded(&egress) {
		t.Fatal("the rule must match the egress port too")
	}
	otherSwitch := ExclusionMatch{SrcAddr: v4(t, "1.1.1.1"), DstAddr: v4(t, "2.2.2.2"), IPVersion: 4, Sampler: other, InIf: 42}
	if f.Excluded(&otherSwitch) {
		t.Fatal("the same ifIndex on another switch must be kept")
	}
	otherPort := ExclusionMatch{SrcAddr: v4(t, "1.1.1.1"), DstAddr: v4(t, "2.2.2.2"), IPVersion: 4, Sampler: sampler, InIf: 7}
	if f.Excluded(&otherPort) {
		t.Fatal("another port on the named switch must be kept")
	}
}

func TestExclusionIPv6(t *testing.T) {
	f := newTestFilter(t, rule("r1", "2001:db8::/32", 6, "any", 0, 0, 0, "any", 0, "", 0, ""))

	hit := ExclusionMatch{SrcAddr: v6(t, "2001:db8::1"), DstAddr: v6(t, "2606:4700::1"), IPVersion: 6}
	if !f.Excluded(&hit) {
		t.Fatal("IPv6 prefix must match")
	}
	miss := ExclusionMatch{SrcAddr: v6(t, "2001:db9::1"), DstAddr: v6(t, "2606:4700::1"), IPVersion: 6}
	if f.Excluded(&miss) {
		t.Fatal("IPv6 address outside the prefix must be kept")
	}
}

func TestExclusionSourceIDScope(t *testing.T) {
	f := newTestFilter(t, rule("r1", "10.0.0.0/8", 4, "any", 0, 0, 0, "any", 0, "", 0, "sflow-a"))

	scoped := ExclusionMatch{SrcAddr: v4(t, "10.1.1.1"), DstAddr: v4(t, "8.8.8.8"), IPVersion: 4, SourceID: "sflow-a"}
	if !f.Excluded(&scoped) {
		t.Fatal("rule must apply to its own source_id")
	}
	elsewhere := ExclusionMatch{SrcAddr: v4(t, "10.1.1.1"), DstAddr: v4(t, "8.8.8.8"), IPVersion: 4, SourceID: "xdp-main"}
	if f.Excluded(&elsewhere) {
		t.Fatal("rule must not apply to another source_id")
	}
}

// A rule with no condition would silently drop all traffic, so the loader has
// to reject it instead.
func TestExclusionRejectsUnconditionalRule(t *testing.T) {
	if _, _, ok := buildExclusionRule("empty", "", 0, "any", 0, 0, 0, "any", 0, "", 0, ""); ok {
		t.Fatal("a rule with no match condition must be rejected")
	}
	if _, _, ok := buildExclusionRule("bad-prefix", "not-a-prefix", 4, "any", 0, 0, 0, "any", 0, "", 0, ""); ok {
		t.Fatal("an unparseable prefix must be rejected")
	}
	if _, _, ok := buildExclusionRule("orphan-ifindex", "", 0, "any", 0, 0, 0, "any", 0, "", 42, ""); ok {
		t.Fatal("an ifIndex without a switch must be rejected")
	}
	if _, _, ok := buildExclusionRule("family-mismatch", "10.0.0.0/8", 6, "any", 0, 0, 0, "any", 0, "", 0, ""); ok {
		t.Fatal("prefix that contradicts the declared family must be rejected")
	}
}

func TestFilterRowsDropsAndCounts(t *testing.T) {
	f := newTestFilter(t, rule("r1", "10.10.0.0/16", 4, "any", 0, 0, 0, "any", 0, "", 0, ""))

	rows := []FlowRow{
		{SrcAddr: v4(t, "10.10.0.1"), DstAddr: v4(t, "8.8.8.8"), Etype: 0x0800, Packets: 3, Bytes: 300},
		{SrcAddr: v4(t, "1.1.1.1"), DstAddr: v4(t, "8.8.8.8"), Etype: 0x0800, Packets: 5, Bytes: 500},
		{SrcAddr: v4(t, "2.2.2.2"), DstAddr: v4(t, "10.10.0.9"), Etype: 0x0800, Packets: 7, Bytes: 700},
	}
	kept := f.FilterRows(rows)

	if len(kept) != 1 {
		t.Fatalf("kept %d rows, want 1", len(kept))
	}
	if kept[0].SrcAddr != v4(t, "1.1.1.1") {
		t.Fatalf("kept the wrong row: %v", kept[0].SrcAddr)
	}
	st := f.Stats()
	if st.Rows != 2 || st.Packets != 10 || st.Bytes != 1000 {
		t.Fatalf("stats = %+v, want rows=2 packets=10 bytes=1000", st)
	}
}

func TestNilFilterIsNoOp(t *testing.T) {
	var f *ExclusionFilter
	rows := []FlowRow{{Packets: 1}}
	if got := f.FilterRows(rows); len(got) != 1 {
		t.Fatal("a nil filter must pass every row through")
	}
	if f.Excluded(&ExclusionMatch{}) {
		t.Fatal("a nil filter must never exclude")
	}
	if f.Stats().Rules != 0 {
		t.Fatal("a nil filter must report no rules")
	}
}

func TestEmptyCatalogKeepsEverything(t *testing.T) {
	f := newTestFilter(t)
	rows := []FlowRow{{SrcAddr: v4(t, "10.10.0.1"), Etype: 0x0800, Packets: 1}}
	if got := f.FilterRows(rows); len(got) != 1 {
		t.Fatal("an empty catalog must not drop anything")
	}
}
