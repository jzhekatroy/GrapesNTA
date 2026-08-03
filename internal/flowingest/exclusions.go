package flowingest

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// DefaultExclusionsTable is the operator-managed view of enabled rules.
const DefaultExclusionsTable = "default.net_flow_exclusions_enabled"

// Which side of a flow a rule constrains.
const (
	exclSideAny uint8 = iota
	exclSideSrc
	exclSideDst
)

// ExclusionMatch is the subset of a flow an exclusion rule can test. Both the
// xdpflowd BPF key and a decoded sFlow FlowRow collapse into this shape, so the
// two collectors share one rule engine and one set of counters.
type ExclusionMatch struct {
	SrcAddr   [16]byte
	DstAddr   [16]byte
	IPVersion uint8
	Proto     uint8
	SrcPort   uint16
	DstPort   uint16
	SrcVLAN   uint16
	DstVLAN   uint16
	Sampler   [16]byte
	InIf      uint32
	OutIf     uint32
	SourceID  string
}

// ExclusionConfig wires the filter to the ClickHouse rule catalog. An empty
// Table or Enabled=false disables filtering entirely.
type ExclusionConfig struct {
	Enabled bool
	DSN     string
	Refresh time.Duration
	Table   string
}

// ExclusionRuleSpec is one catalog row before parsing. Exported so a filter can
// be built without ClickHouse.
type ExclusionRuleSpec struct {
	RuleID    string
	Prefix    string
	Family    uint8
	MatchSide string
	Proto     uint8
	PortFrom  uint16
	PortTo    uint16
	PortSide  string
	VLANID    uint16
	SwitchIP  string
	IfIndex   uint32
	SourceID  string
}

// ExclusionStats reports what the filter has dropped since process start.
type ExclusionStats struct {
	Rules   int
	Rows    uint64
	Packets uint64
	Bytes   uint64
}

// exclusionRule is one operator rule, pre-parsed for the hot path. Every
// non-zero field is an additional AND condition; a zero field means "any".
type exclusionRule struct {
	id        string
	side      uint8
	hasPrefix bool
	proto     uint8
	hasPort   bool
	portFrom  uint16
	portTo    uint16
	portSide  uint8
	vlan      uint16
	hasSwitch bool
	sampler   [16]byte
	ifIndex   uint32
	sourceID  string
}

type exclusionState struct {
	rules  []exclusionRule
	v4     *exclTrie
	v6     *exclTrie
	global []int32
}

// ExclusionFilter drops flows matched by the operator rule catalog. A nil
// filter is a no-op, so callers can wire it unconditionally.
type ExclusionFilter struct {
	log    *slog.Logger
	conn   chdriver.Conn
	cfg    ExclusionConfig
	cancel context.CancelFunc
	state  atomic.Pointer[exclusionState]

	rowsExcluded    atomic.Uint64
	packetsExcluded atomic.Uint64
	bytesExcluded   atomic.Uint64
}

// NewExclusionFilter returns nil when the feature is off. Unlike the traffic
// classifier, a load failure never blocks startup: the catalog is optional and
// an unreachable table must not stop ingest. The filter then runs with zero
// rules (nothing is dropped) until a refresh succeeds.
func NewExclusionFilter(ctx context.Context, log *slog.Logger, cfg ExclusionConfig) (*ExclusionFilter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	cfg.Table = strings.TrimSpace(cfg.Table)
	if cfg.Table == "" {
		return nil, nil
	}
	if strings.TrimSpace(cfg.DSN) == "" {
		return nil, fmt.Errorf("flow exclusions require -ch-dsn")
	}
	if cfg.Refresh <= 0 {
		cfg.Refresh = time.Minute
	}
	opts, err := ParseClickHouseDSN(cfg.DSN)
	if err != nil {
		return nil, err
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("flow exclusions clickhouse open: %w", err)
	}
	fctx, cancel := context.WithCancel(ctx)
	f := &ExclusionFilter{log: log, conn: conn, cfg: cfg, cancel: cancel}
	f.state.Store(emptyExclusionState())
	if err := f.refreshOnce(fctx); err != nil {
		log.Warn("flow exclusions initial load failed; starting with no rules",
			"table", cfg.Table, "err", err)
	}
	go f.run(fctx)
	log.Info("flow exclusions enabled", "table", cfg.Table, "refresh", cfg.Refresh)
	return f, nil
}

func (f *ExclusionFilter) Close() {
	if f == nil {
		return
	}
	f.cancel()
	if f.conn != nil {
		_ = f.conn.Close()
	}
}

func (f *ExclusionFilter) run(ctx context.Context) {
	ticker := time.NewTicker(f.cfg.Refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := f.refreshOnce(ctx); err != nil {
				f.log.Warn("flow exclusions refresh failed", "table", f.cfg.Table, "err", err)
			}
		}
	}
}

func emptyExclusionState() *exclusionState {
	return &exclusionState{v4: newExclTrie(), v6: newExclTrie()}
}

func (f *ExclusionFilter) refreshOnce(ctx context.Context) error {
	rows, err := f.conn.Query(ctx, "SELECT rule_id, prefix, family, match_side, proto, "+
		"port_from, port_to, port_side, vlan_id, switch_ip, if_index, source_id FROM "+f.cfg.Table)
	if err != nil {
		return fmt.Errorf("load flow exclusions: %w", err)
	}
	defer rows.Close()

	var specs []ExclusionRuleSpec
	for rows.Next() {
		var s ExclusionRuleSpec
		if err := rows.Scan(&s.RuleID, &s.Prefix, &s.Family, &s.MatchSide, &s.Proto,
			&s.PortFrom, &s.PortTo, &s.PortSide, &s.VLANID, &s.SwitchIP, &s.IfIndex,
			&s.SourceID); err != nil {
			return fmt.Errorf("scan flow exclusions: %w", err)
		}
		specs = append(specs, s)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read flow exclusions: %w", err)
	}

	st, rejected := buildExclusionState(specs)
	for _, id := range rejected {
		f.log.Warn("flow exclusion rule ignored", "rule_id", id,
			"reason", "no usable match condition or unparseable prefix")
	}
	f.state.Store(st)
	f.log.Info("flow exclusions refreshed",
		"table", f.cfg.Table,
		"rules", len(st.rules),
		"prefix_rules", len(st.rules)-len(st.global),
		"global_rules", len(st.global),
		"skipped", len(rejected),
	)
	return nil
}

// NewStaticExclusionFilter builds a filter over a fixed rule set, with no
// ClickHouse connection and no refresh. It returns the ids of rules that were
// rejected as unusable.
func NewStaticExclusionFilter(specs []ExclusionRuleSpec) (*ExclusionFilter, []string) {
	st, rejected := buildExclusionState(specs)
	f := &ExclusionFilter{}
	f.state.Store(st)
	return f, rejected
}

func buildExclusionState(specs []ExclusionRuleSpec) (*exclusionState, []string) {
	st := emptyExclusionState()
	var rejected []string
	for _, s := range specs {
		rule, pfx, ok := buildExclusionRule(s.RuleID, s.Prefix, s.Family, s.MatchSide,
			s.Proto, s.PortFrom, s.PortTo, s.PortSide, s.VLANID, s.SwitchIP, s.IfIndex,
			s.SourceID)
		if !ok {
			rejected = append(rejected, s.RuleID)
			continue
		}
		idx := int32(len(st.rules))
		st.rules = append(st.rules, rule)
		if !rule.hasPrefix {
			st.global = append(st.global, idx)
			continue
		}
		if pfx.Addr().Is4() {
			st.v4.insert(pfx, idx)
		} else {
			st.v6.insert(pfx, idx)
		}
	}
	return st, rejected
}

// buildExclusionRule validates one catalog row. A rule with no condition at all
// would silently drop every flow, so it is rejected rather than applied.
func buildExclusionRule(ruleID, prefix string, family uint8, matchSide string, proto uint8,
	portFrom, portTo uint16, portSide string, vlanID uint16, switchIP string, ifIndex uint32,
	sourceID string) (exclusionRule, netip.Prefix, bool) {
	r := exclusionRule{
		id:       strings.TrimSpace(ruleID),
		side:     parseExclSide(matchSide),
		proto:    proto,
		portSide: parseExclSide(portSide),
		vlan:     vlanID,
		ifIndex:  ifIndex,
		sourceID: strings.TrimSpace(sourceID),
	}

	var pfx netip.Prefix
	if p := strings.TrimSpace(prefix); p != "" {
		parsed, err := netip.ParsePrefix(p)
		if err != nil || !parsed.IsValid() {
			return r, pfx, false
		}
		if family == 4 && !parsed.Addr().Is4() {
			return r, pfx, false
		}
		if family == 6 && parsed.Addr().Is4() {
			return r, pfx, false
		}
		pfx = parsed.Masked()
		r.hasPrefix = true
	}

	if portFrom != 0 || portTo != 0 {
		lo, hi := portFrom, portTo
		if hi == 0 {
			hi = lo
		}
		if lo == 0 {
			lo = hi
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		r.hasPort = true
		r.portFrom = lo
		r.portTo = hi
	}

	if s := strings.TrimSpace(switchIP); s != "" {
		sampler, err := ParseSamplerAddress(s)
		if err != nil || sampler == ([16]byte{}) {
			return r, pfx, false
		}
		r.sampler = sampler
		r.hasSwitch = true
	}
	// An ifIndex without a switch would match the same port number on every
	// exporter, which is never what an operator means.
	if r.ifIndex != 0 && !r.hasSwitch {
		return r, pfx, false
	}

	if !r.hasPrefix && !r.hasPort && r.proto == 0 && r.vlan == 0 && !r.hasSwitch && r.sourceID == "" {
		return r, pfx, false
	}
	return r, pfx, true
}

func parseExclSide(s string) uint8 {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "src", "source":
		return exclSideSrc
	case "dst", "destination":
		return exclSideDst
	default:
		return exclSideAny
	}
}

// Rules reports how many rules are currently loaded.
func (f *ExclusionFilter) Rules() int {
	if f == nil {
		return 0
	}
	st := f.state.Load()
	if st == nil {
		return 0
	}
	return len(st.rules)
}

// Stats returns cumulative drop counters plus the active rule count.
func (f *ExclusionFilter) Stats() ExclusionStats {
	if f == nil {
		return ExclusionStats{}
	}
	return ExclusionStats{
		Rules:   f.Rules(),
		Rows:    f.rowsExcluded.Load(),
		Packets: f.packetsExcluded.Load(),
		Bytes:   f.bytesExcluded.Load(),
	}
}

// Count records one dropped flow record. Callers that decide exclusion through
// Excluded must call this so health snapshots can correct the completeness
// ratio for traffic the collector deliberately discarded.
func (f *ExclusionFilter) Count(packets, bytes uint64) {
	if f == nil {
		return
	}
	f.rowsExcluded.Add(1)
	f.packetsExcluded.Add(packets)
	f.bytesExcluded.Add(bytes)
}

// Excluded reports whether any enabled rule matches the flow.
func (f *ExclusionFilter) Excluded(m *ExclusionMatch) bool {
	if f == nil || m == nil {
		return false
	}
	st := f.state.Load()
	if st == nil || len(st.rules) == 0 {
		return false
	}

	for _, idx := range st.global {
		if st.rules[idx].matchesNonPrefix(m) {
			return true
		}
	}

	if src, ok := addrFromFlow(m.SrcAddr, m.IPVersion); ok {
		if st.prefixHit(src, exclSideSrc, m) {
			return true
		}
	}
	if dst, ok := addrFromFlow(m.DstAddr, m.IPVersion); ok {
		if st.prefixHit(dst, exclSideDst, m) {
			return true
		}
	}
	return false
}

func (st *exclusionState) prefixHit(addr netip.Addr, side uint8, m *ExclusionMatch) bool {
	trie := st.v4
	if !addr.Is4() {
		trie = st.v6
	}
	return trie.walk(addr, func(idx int32) bool {
		r := &st.rules[idx]
		if r.side != exclSideAny && r.side != side {
			return false
		}
		return r.matchesNonPrefix(m)
	})
}

// matchesNonPrefix checks every condition except the prefix, which the caller
// has already resolved through the trie.
func (r *exclusionRule) matchesNonPrefix(m *ExclusionMatch) bool {
	if r.sourceID != "" && r.sourceID != m.SourceID {
		return false
	}
	if r.proto != 0 && r.proto != m.Proto {
		return false
	}
	if r.vlan != 0 && r.vlan != m.SrcVLAN && r.vlan != m.DstVLAN {
		return false
	}
	if r.hasSwitch {
		if r.sampler != m.Sampler {
			return false
		}
		if r.ifIndex != 0 && r.ifIndex != m.InIf && r.ifIndex != m.OutIf {
			return false
		}
	}
	if r.hasPort && !r.portMatches(m) {
		return false
	}
	return true
}

func (r *exclusionRule) portMatches(m *ExclusionMatch) bool {
	switch r.portSide {
	case exclSideSrc:
		return m.SrcPort >= r.portFrom && m.SrcPort <= r.portTo
	case exclSideDst:
		return m.DstPort >= r.portFrom && m.DstPort <= r.portTo
	default:
		return (m.SrcPort >= r.portFrom && m.SrcPort <= r.portTo) ||
			(m.DstPort >= r.portFrom && m.DstPort <= r.portTo)
	}
}

// FilterRows drops excluded rows in place and returns the kept prefix of the
// slice. The input backing array is reused, so callers must not hold on to the
// original slice afterwards.
func (f *ExclusionFilter) FilterRows(rows []FlowRow) []FlowRow {
	if f == nil || len(rows) == 0 {
		return rows
	}
	st := f.state.Load()
	if st == nil || len(st.rules) == 0 {
		return rows
	}
	kept := rows[:0]
	for i := range rows {
		m := matchFromRow(&rows[i])
		if f.Excluded(&m) {
			f.Count(rows[i].Packets, rows[i].Bytes)
			continue
		}
		kept = append(kept, rows[i])
	}
	return kept
}

func matchFromRow(r *FlowRow) ExclusionMatch {
	return ExclusionMatch{
		SrcAddr:   r.SrcAddr,
		DstAddr:   r.DstAddr,
		IPVersion: IPVersionFromEtype(r.Etype),
		Proto:     uint8(r.Proto),
		SrcPort:   uint16(r.SrcPort),
		DstPort:   uint16(r.DstPort),
		SrcVLAN:   r.SrcVLAN,
		DstVLAN:   r.DstVLAN,
		Sampler:   r.SamplerAddress,
		InIf:      r.InIf,
		OutIf:     r.OutIf,
		SourceID:  r.SourceID,
	}
}

// exclTrie maps prefixes to rule indices. Unlike the classifier trie it keeps
// every rule along the path instead of only the longest match: two rules on
// overlapping prefixes may carry different port or protocol conditions, so both
// have to be evaluated.
type exclTrie struct {
	root *exclTrieNode
}

type exclTrieNode struct {
	child [2]*exclTrieNode
	rules []int32
}

func newExclTrie() *exclTrie {
	return &exclTrie{root: &exclTrieNode{}}
}

func (t *exclTrie) insert(prefix netip.Prefix, idx int32) {
	if t == nil || !prefix.IsValid() {
		return
	}
	n := t.root
	addr := prefix.Addr()
	for i := 0; i < prefix.Bits(); i++ {
		bit := trieBit(addr, i)
		if n.child[bit] == nil {
			n.child[bit] = &exclTrieNode{}
		}
		n = n.child[bit]
	}
	n.rules = append(n.rules, idx)
}

// walk calls fn for every rule whose prefix contains addr and stops at the
// first fn that returns true.
func (t *exclTrie) walk(addr netip.Addr, fn func(int32) bool) bool {
	if t == nil || t.root == nil || !addr.IsValid() {
		return false
	}
	n := t.root
	for _, idx := range n.rules {
		if fn(idx) {
			return true
		}
	}
	maxBits := 128
	if addr.Is4() {
		maxBits = 32
	}
	for i := 0; i < maxBits; i++ {
		n = n.child[trieBit(addr, i)]
		if n == nil {
			return false
		}
		for _, idx := range n.rules {
			if fn(idx) {
				return true
			}
		}
	}
	return false
}
