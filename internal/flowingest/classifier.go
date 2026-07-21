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

type ClassifierTables struct {
	BGPOrigins    string
	IPASNPrefixes string
	L3Prefixes    string
	L2VLANs       string
}

type ClassifierConfig struct {
	Enabled bool
	DSN     string
	Refresh time.Duration
	Tables  ClassifierTables
}

type TrafficClassifier struct {
	log    *slog.Logger
	conn   chdriver.Conn
	cfg    ClassifierConfig
	cancel context.CancelFunc
	state  atomic.Pointer[classifierState]
}

type classifierState struct {
	bgp4 *ipTrie
	bgp6 *ipTrie
	asn4 *ipTrie
	asn6 *ipTrie
	l3v4 *ipTrie
	l3v6 *ipTrie

	vlans map[uint16]vlanClass

	hasLocalConfig bool
}

type vlanClass struct {
	EntityID       string
	AttachmentType string
	Boundary       string
	DisplayName    string
}

type prefixClass struct {
	ASN         uint32
	Role        string
	EntityID    string
	DisplayName string
}

type EndpointClass struct {
	ASN           uint32
	Role          string
	Entity        string
	DisplayName   string
	Source        string
	Scope         string
	NetworkName   string
	NetworkRole   string
	Label         string
	OperatorID    string
	Attachment    attachmentClass
}

type attachmentClass struct {
	Kind       string
	Boundary   string
	Label      string
	OperatorID string
}

func NewTrafficClassifier(ctx context.Context, log *slog.Logger, cfg ClassifierConfig) (*TrafficClassifier, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if strings.TrimSpace(cfg.DSN) == "" {
		return nil, fmt.Errorf("classifier requires -ch-dsn")
	}
	if cfg.Refresh <= 0 {
		cfg.Refresh = time.Minute
	}
	cfg.Tables = cfg.Tables.withDefaults()
	opts, err := ParseClickHouseDSN(cfg.DSN)
	if err != nil {
		return nil, err
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("classifier clickhouse open: %w", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	tc := &TrafficClassifier{
		log:    log,
		conn:   conn,
		cfg:    cfg,
		cancel: cancel,
	}
	if err := tc.refreshOnce(cctx); err != nil {
		_ = conn.Close()
		cancel()
		return nil, err
	}
	go tc.run(cctx)
	log.Info("traffic classifier enabled",
		"refresh", cfg.Refresh,
		"bgp_table", cfg.Tables.BGPOrigins,
		"ip_asn_table", cfg.Tables.IPASNPrefixes,
		"l3_prefixes", cfg.Tables.L3Prefixes,
		"l2_vlans", cfg.Tables.L2VLANs,
	)
	return tc, nil
}

func (t ClassifierTables) withDefaults() ClassifierTables {
	if strings.TrimSpace(t.BGPOrigins) == "" {
		t.BGPOrigins = "default.bgp_prefix_origin_current"
	}
	if strings.TrimSpace(t.L3Prefixes) == "" {
		t.L3Prefixes = "default.net_l3_prefixes_enabled"
	}
	if strings.TrimSpace(t.L2VLANs) == "" {
		t.L2VLANs = "default.net_l2_vlans_enabled"
	}
	return t
}

func (tc *TrafficClassifier) Close() {
	if tc == nil {
		return
	}
	tc.cancel()
	if tc.conn != nil {
		_ = tc.conn.Close()
	}
}

func (tc *TrafficClassifier) run(ctx context.Context) {
	ticker := time.NewTicker(tc.cfg.Refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := tc.refreshOnce(ctx); err != nil {
				tc.log.Warn("traffic classifier refresh failed", "err", err)
			}
		}
	}
}

func (tc *TrafficClassifier) refreshOnce(ctx context.Context) error {
	start := time.Now()
	st := &classifierState{
		bgp4:   newIPTrie(),
		bgp6:   newIPTrie(),
		asn4:   newIPTrie(),
		asn6:   newIPTrie(),
		l3v4:   newIPTrie(),
		l3v6:   newIPTrie(),
		vlans:  make(map[uint16]vlanClass),
	}
	bgpRows, err := tc.loadBGP(ctx, st)
	if err != nil {
		return err
	}
	ipASNRows, err := tc.loadIPASNPrefixes(ctx, st)
	if err != nil {
		return err
	}
	l3Rows, err := tc.loadL3Prefixes(ctx, st)
	if err != nil {
		return err
	}
	vlanRows, internalVLANs, err := tc.loadL2VLANs(ctx, st)
	if err != nil {
		return err
	}
	st.hasLocalConfig = l3Rows > 0
	tc.state.Store(st)
	tc.log.Info("traffic classifier refreshed",
		"bgp_prefixes", bgpRows,
		"ip_asn_prefixes", ipASNRows,
		"l3_prefixes", l3Rows,
		"vlans", vlanRows,
		"internal_vlans", internalVLANs,
		"has_local_config", st.hasLocalConfig,
		"elapsed", time.Since(start),
	)
	return nil
}

func (tc *TrafficClassifier) loadBGP(ctx context.Context, st *classifierState) (int, error) {
	rows, err := tc.conn.Query(ctx, "SELECT prefix, origin_asn FROM "+tc.cfg.Tables.BGPOrigins)
	if err != nil {
		return 0, fmt.Errorf("load BGP origins: %w", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var prefix string
		var asn uint32
		if err := rows.Scan(&prefix, &asn); err != nil {
			return n, err
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(prefix))
		if err != nil || !p.IsValid() || asn == 0 {
			continue
		}
		if p.Bits() == 0 {
			// A default route is not an origin route; using it would classify all
			// unmatched remote IPs as the default route's transit ASN.
			continue
		}
		if p.Addr().Is4() {
			st.bgp4.Insert(p.Masked(), prefixClass{ASN: asn})
		} else {
			st.bgp6.Insert(p.Masked(), prefixClass{ASN: asn})
		}
		n++
	}
	return n, rows.Err()
}

func (tc *TrafficClassifier) loadIPASNPrefixes(ctx context.Context, st *classifierState) (int, error) {
	if strings.TrimSpace(tc.cfg.Tables.IPASNPrefixes) == "" {
		return 0, nil
	}
	rows, err := tc.conn.Query(ctx, "SELECT prefix, origin_asn FROM "+tc.cfg.Tables.IPASNPrefixes)
	if err != nil {
		return 0, fmt.Errorf("load IP ASN prefixes: %w", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var prefix string
		var asn uint32
		if err := rows.Scan(&prefix, &asn); err != nil {
			return n, err
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(prefix))
		if err != nil || !p.IsValid() || asn == 0 {
			continue
		}
		if p.Addr().Is4() {
			st.asn4.Insert(p.Masked(), prefixClass{ASN: asn})
		} else {
			st.asn6.Insert(p.Masked(), prefixClass{ASN: asn})
		}
		n++
	}
	return n, rows.Err()
}

func (tc *TrafficClassifier) loadL3Prefixes(ctx context.Context, st *classifierState) (int, error) {
	rows, err := tc.conn.Query(ctx, "SELECT prefix, family, entity_id, role, display_name, origin_asn FROM "+tc.cfg.Tables.L3Prefixes)
	if err != nil {
		return 0, fmt.Errorf("load L3 prefixes: %w", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var prefix, entityID, role, displayName string
		var family uint8
		var originASN uint32
		if err := rows.Scan(&prefix, &family, &entityID, &role, &displayName, &originASN); err != nil {
			return n, err
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(prefix))
		if err != nil || !p.IsValid() {
			continue
		}
		role = normalizeRole(role)
		pc := prefixClass{ASN: originASN, Role: role, EntityID: entityID, DisplayName: displayName}
		if family == 4 || p.Addr().Is4() {
			st.l3v4.Insert(p.Masked(), pc)
		} else {
			st.l3v6.Insert(p.Masked(), pc)
		}
		n++
	}
	return n, rows.Err()
}

func (tc *TrafficClassifier) loadL2VLANs(ctx context.Context, st *classifierState) (rowsCount int, internalCount int, err error) {
	rows, err := tc.conn.Query(ctx, "SELECT vlan_id, entity_id, attachment_type, boundary, display_name FROM "+tc.cfg.Tables.L2VLANs)
	if err != nil {
		return 0, 0, fmt.Errorf("load L2 VLANs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var vlan uint16
		var entityID, attachmentType, boundary, displayName string
		if err := rows.Scan(&vlan, &entityID, &attachmentType, &boundary, &displayName); err != nil {
			return rowsCount, internalCount, err
		}
		if vlan == 0 {
			continue
		}
		attachmentType = normalizeAttachmentType(attachmentType)
		boundary = normalizeBoundary(boundary, attachmentType)
		st.vlans[vlan] = vlanClass{
			EntityID:       entityID,
			AttachmentType: attachmentType,
			Boundary:       boundary,
			DisplayName:    displayName,
		}
		rowsCount++
		if boundary == "internal" {
			internalCount++
		}
	}
	return rowsCount, internalCount, rows.Err()
}

func (tc *TrafficClassifier) ClassifyPair(src, dst [16]byte, ipVersion uint8, srcVLAN, dstVLAN uint16) (EndpointClass, EndpointClass, string) {
	if tc == nil {
		return EndpointClass{Scope: "unknown", Source: "unknown"}, EndpointClass{Scope: "unknown", Source: "unknown"}, "unknown"
	}
	st := tc.state.Load()
	if st == nil {
		return EndpointClass{Scope: "unknown", Source: "unknown"}, EndpointClass{Scope: "unknown", Source: "unknown"}, "unknown"
	}
	srcAddr, okSrc := addrFromFlow(src, ipVersion)
	dstAddr, okDst := addrFromFlow(dst, ipVersion)
	if !okSrc || !okDst {
		return EndpointClass{Scope: "unknown", Source: "unknown"}, EndpointClass{Scope: "unknown", Source: "unknown"}, "unknown"
	}
	srcClass := st.classify(srcAddr, srcVLAN)
	dstClass := st.classify(dstAddr, dstVLAN)
	return srcClass, dstClass, DeriveDirection(srcClass, dstClass)
}

func (st *classifierState) classify(addr netip.Addr, vlan uint16) EndpointClass {
	asn := st.lookupASN(addr)
	att := st.lookupAttachment(vlan)
	if p, ok := st.lookupL3Prefix(addr); ok {
		if p.ASN != 0 {
			asn = p.ASN
		}
		role := normalizeRole(p.Role)
		scope := scopeFromRole(role)
		return EndpointClass{
			ASN:         asn,
			Role:        role,
			Entity:      p.EntityID,
			DisplayName: p.DisplayName,
			Source:      "prefix",
			Scope:       scope,
			NetworkName: p.DisplayName,
			NetworkRole: role,
			Label:       p.DisplayName,
			OperatorID:  p.EntityID,
			Attachment:  att,
		}
	}
	return EndpointClass{
		ASN:         asn,
		Role:        "remote",
		Entity:      "",
		Source:      "fallback",
		Scope:       "remote",
		NetworkRole: "remote",
		Attachment:  att,
	}
}

func (st *classifierState) lookupAttachment(vlan uint16) attachmentClass {
	if vlan == 0 {
		return attachmentClass{Kind: "unknown", Boundary: "unknown"}
	}
	if v, ok := st.vlans[vlan]; ok {
		return attachmentClass{
			Kind:       v.AttachmentType,
			Boundary:   v.Boundary,
			Label:      v.DisplayName,
			OperatorID: v.EntityID,
		}
	}
	return attachmentClass{Kind: "unknown", Boundary: "unknown"}
}

func (st *classifierState) lookupASN(addr netip.Addr) uint32 {
	if addr.Is4() {
		if p, ok := st.bgp4.Lookup(addr); ok {
			return p.ASN
		}
		if p, ok := st.asn4.Lookup(addr); ok {
			return p.ASN
		}
		return 0
	}
	if p, ok := st.bgp6.Lookup(addr); ok {
		return p.ASN
	}
	if p, ok := st.asn6.Lookup(addr); ok {
		return p.ASN
	}
	return 0
}

func (st *classifierState) lookupL3Prefix(addr netip.Addr) (prefixClass, bool) {
	if addr.Is4() {
		return st.l3v4.Lookup(addr)
	}
	return st.l3v6.Lookup(addr)
}

// DeriveDirection maps endpoint roles to traffic direction.
// Unmatched addresses are role=remote, so with an empty L3 catalog both sides
// are remote → transit (not "unknown"). "unknown" is reserved for classifier
// off / unparseable endpoints, not for "networks not labeled yet".
func DeriveDirection(src, dst EndpointClass) string {
	srcLocal := isLocalOrCustomerRole(src.Role)
	dstLocal := isLocalOrCustomerRole(dst.Role)
	switch {
	case srcLocal && dstLocal:
		return "internal"
	case srcLocal && !dstLocal:
		return "out"
	case !srcLocal && dstLocal:
		return "in"
	default:
		return "transit"
	}
}

func normalizeRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	switch role {
	case "provider_public", "internal", "customer_allocated", "customer_transit", "remote":
		return role
	default:
		if role == "" {
			return "remote"
		}
		return role
	}
}

func normalizeAttachmentType(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		return "unknown"
	}
	return kind
}

func normalizeBoundary(boundary, attachmentType string) string {
	boundary = strings.ToLower(strings.TrimSpace(boundary))
	switch boundary {
	case "internal", "external":
		return boundary
	}
	switch normalizeAttachmentType(attachmentType) {
	case "customer", "internal", "core":
		return "internal"
	case "uplink", "ix", "peering":
		return "external"
	default:
		return "unknown"
	}
}

func scopeFromRole(role string) string {
	switch normalizeRole(role) {
	case "provider_public", "internal":
		return "local"
	case "customer_allocated", "customer_transit":
		return "customer"
	default:
		return "remote"
	}
}

func isLocalOrCustomerRole(role string) bool {
	switch normalizeRole(role) {
	case "provider_public", "internal", "customer_allocated", "customer_transit":
		return true
	default:
		return false
	}
}

func addrFromFlow(raw [16]byte, ipVersion uint8) (netip.Addr, bool) {
	switch ipVersion {
	case 4:
		return netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]}), true
	case 6:
		return netip.AddrFrom16(raw), true
	default:
		return netip.Addr{}, false
	}
}

type ipTrie struct {
	root *ipTrieNode
}

type ipTrieNode struct {
	child [2]*ipTrieNode
	value *prefixClass
}

func newIPTrie() *ipTrie {
	return &ipTrie{root: &ipTrieNode{}}
}

func (t *ipTrie) Insert(prefix netip.Prefix, value prefixClass) {
	if t == nil || !prefix.IsValid() {
		return
	}
	n := t.root
	addr := prefix.Addr()
	bits := prefix.Bits()
	for i := 0; i < bits; i++ {
		bit := trieBit(addr, i)
		if n.child[bit] == nil {
			n.child[bit] = &ipTrieNode{}
		}
		n = n.child[bit]
	}
	v := value
	n.value = &v
}

func (t *ipTrie) Lookup(addr netip.Addr) (prefixClass, bool) {
	if t == nil || t.root == nil || !addr.IsValid() {
		return prefixClass{}, false
	}
	n := t.root
	var best *prefixClass
	if n.value != nil {
		best = n.value
	}
	maxBits := 128
	if addr.Is4() {
		maxBits = 32
	}
	for i := 0; i < maxBits; i++ {
		bit := trieBit(addr, i)
		n = n.child[bit]
		if n == nil {
			break
		}
		if n.value != nil {
			best = n.value
		}
	}
	if best == nil {
		return prefixClass{}, false
	}
	return *best, true
}

func trieBit(addr netip.Addr, pos int) int {
	if addr.Is4() {
		a := addr.As4()
		return int((a[pos/8] >> uint(7-pos%8)) & 1)
	}
	a := addr.As16()
	return int((a[pos/8] >> uint(7-pos%8)) & 1)
}
