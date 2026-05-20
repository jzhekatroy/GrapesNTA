package main

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

type classifierTables struct {
	BGPOrigins    string
	LocalNetworks string
	LocalASNs     string
	VLANMap       string
}

type classifierConfig struct {
	Enabled bool
	DSN     string
	Refresh time.Duration
	Tables  classifierTables
}

type trafficClassifier struct {
	log    *slog.Logger
	conn   chdriver.Conn
	cfg    classifierConfig
	cancel context.CancelFunc
	state  atomic.Pointer[classifierState]
}

type classifierState struct {
	bgp4   *ipTrie
	bgp6   *ipTrie
	local4 *ipTrie
	local6 *ipTrie

	localASNs map[uint32]asnClass
	vlans     map[uint16]vlanClass

	hasLocalConfig bool
}

type asnClass struct {
	OperatorID string
	Name       string
}

type vlanClass struct {
	AttachmentKind     string
	AttachmentBoundary string
	Label              string
	OperatorID         string
}

type prefixClass struct {
	ASN        uint32
	Role       string
	OperatorID string
	Name       string
}

type endpointClass struct {
	ASN           uint32
	Scope         string
	Source        string
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

func newTrafficClassifier(ctx context.Context, log *slog.Logger, cfg classifierConfig) (*trafficClassifier, error) {
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
	opts, err := parseClickHouseDSN(cfg.DSN)
	if err != nil {
		return nil, err
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("classifier clickhouse open: %w", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	tc := &trafficClassifier{
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
		"local_networks", cfg.Tables.LocalNetworks,
		"local_asns", cfg.Tables.LocalASNs,
		"vlan_map", cfg.Tables.VLANMap,
	)
	return tc, nil
}

func (t classifierTables) withDefaults() classifierTables {
	if strings.TrimSpace(t.BGPOrigins) == "" {
		t.BGPOrigins = "default.bgp_prefix_origin_current"
	}
	if strings.TrimSpace(t.LocalNetworks) == "" {
		t.LocalNetworks = "default.local_networks_enabled"
	}
	if strings.TrimSpace(t.LocalASNs) == "" {
		t.LocalASNs = "default.local_asns_enabled"
	}
	if strings.TrimSpace(t.VLANMap) == "" {
		t.VLANMap = "default.vlan_map_enabled"
	}
	return t
}

func (tc *trafficClassifier) Close() {
	if tc == nil {
		return
	}
	tc.cancel()
	if tc.conn != nil {
		_ = tc.conn.Close()
	}
}

func (tc *trafficClassifier) run(ctx context.Context) {
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

func (tc *trafficClassifier) refreshOnce(ctx context.Context) error {
	start := time.Now()
	st := &classifierState{
		bgp4:      newIPTrie(),
		bgp6:      newIPTrie(),
		local4:    newIPTrie(),
		local6:    newIPTrie(),
		localASNs: make(map[uint32]asnClass),
		vlans:     make(map[uint16]vlanClass),
	}
	bgpRows, err := tc.loadBGP(ctx, st)
	if err != nil {
		return err
	}
	localPrefixRows, err := tc.loadLocalNetworks(ctx, st)
	if err != nil {
		return err
	}
	localASNRows, err := tc.loadLocalASNs(ctx, st)
	if err != nil {
		return err
	}
	vlanRows, internalVLANs, err := tc.loadVLANMap(ctx, st)
	if err != nil {
		return err
	}
	st.hasLocalConfig = localPrefixRows > 0 || localASNRows > 0
	tc.state.Store(st)
	tc.log.Info("traffic classifier refreshed",
		"bgp_prefixes", bgpRows,
		"local_prefixes", localPrefixRows,
		"local_asns", localASNRows,
		"vlans", vlanRows,
		"internal_vlans", internalVLANs,
		"has_local_config", st.hasLocalConfig,
		"elapsed", time.Since(start),
	)
	return nil
}

func (tc *trafficClassifier) loadBGP(ctx context.Context, st *classifierState) (int, error) {
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
		if p.Addr().Is4() {
			st.bgp4.Insert(p.Masked(), prefixClass{ASN: asn})
		} else {
			st.bgp6.Insert(p.Masked(), prefixClass{ASN: asn})
		}
		n++
	}
	return n, rows.Err()
}

func (tc *trafficClassifier) loadLocalNetworks(ctx context.Context, st *classifierState) (int, error) {
	rows, err := tc.conn.Query(ctx, "SELECT prefix, family, operator_id, kind, name FROM "+tc.cfg.Tables.LocalNetworks)
	if err != nil {
		return 0, fmt.Errorf("load local networks: %w", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var prefix, operatorID, kind, name string
		var family uint8
		if err := rows.Scan(&prefix, &family, &operatorID, &kind, &name); err != nil {
			return n, err
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(prefix))
		if err != nil || !p.IsValid() {
			continue
		}
		role := normalizeKind(kind, "customer")
		pc := prefixClass{Role: role, OperatorID: operatorID, Name: name}
		if family == 4 || p.Addr().Is4() {
			st.local4.Insert(p.Masked(), pc)
		} else {
			st.local6.Insert(p.Masked(), pc)
		}
		n++
	}
	return n, rows.Err()
}

func (tc *trafficClassifier) loadLocalASNs(ctx context.Context, st *classifierState) (int, error) {
	rows, err := tc.conn.Query(ctx, "SELECT asn, operator_id, name FROM "+tc.cfg.Tables.LocalASNs)
	if err != nil {
		return 0, fmt.Errorf("load local ASNs: %w", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var asn uint32
		var operatorID, name string
		if err := rows.Scan(&asn, &operatorID, &name); err != nil {
			return n, err
		}
		if asn == 0 {
			continue
		}
		st.localASNs[asn] = asnClass{OperatorID: operatorID, Name: name}
		n++
	}
	return n, rows.Err()
}

func (tc *trafficClassifier) loadVLANMap(ctx context.Context, st *classifierState) (rowsCount int, customerCount int, err error) {
	rows, err := tc.conn.Query(ctx, "SELECT vlan_id, attachment_kind, boundary, label, operator_id FROM "+tc.cfg.Tables.VLANMap)
	if err != nil {
		return 0, 0, fmt.Errorf("load VLAN map: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var vlan uint16
		var kind, boundary, label, operatorID string
		if err := rows.Scan(&vlan, &kind, &boundary, &label, &operatorID); err != nil {
			return rowsCount, customerCount, err
		}
		if vlan == 0 {
			continue
		}
		kind = normalizeKind(kind, "unknown")
		boundary = normalizeBoundary(boundary, kind)
		st.vlans[vlan] = vlanClass{
			AttachmentKind:     kind,
			AttachmentBoundary: boundary,
			Label:              label,
			OperatorID:         operatorID,
		}
		rowsCount++
		if boundary == "internal" {
			customerCount++
		}
	}
	return rowsCount, customerCount, rows.Err()
}

func (tc *trafficClassifier) classifyPair(src, dst [16]byte, ipVersion uint8, srcVLAN, dstVLAN uint16) (endpointClass, endpointClass, string) {
	if tc == nil {
		return endpointClass{Scope: "unknown", Source: "unknown"}, endpointClass{Scope: "unknown", Source: "unknown"}, "unknown"
	}
	st := tc.state.Load()
	if st == nil {
		return endpointClass{Scope: "unknown", Source: "unknown"}, endpointClass{Scope: "unknown", Source: "unknown"}, "unknown"
	}
	srcAddr, okSrc := addrFromFlow(src, ipVersion)
	dstAddr, okDst := addrFromFlow(dst, ipVersion)
	if !okSrc || !okDst {
		return endpointClass{Scope: "unknown", Source: "unknown"}, endpointClass{Scope: "unknown", Source: "unknown"}, "unknown"
	}
	srcClass := st.classify(srcAddr, srcVLAN)
	dstClass := st.classify(dstAddr, dstVLAN)
	return srcClass, dstClass, deriveDirection(st.hasLocalConfig, srcClass, dstClass)
}

func (st *classifierState) classify(addr netip.Addr, vlan uint16) endpointClass {
	asn := st.lookupASN(addr)
	att := st.lookupAttachment(vlan)
	if vlan != 0 {
		att = st.lookupAttachment(vlan)
	}
	if asn != 0 {
		if a, ok := st.localASNs[asn]; ok {
			return endpointClass{
				ASN:        asn,
				Scope:      "local",
				Source:     "asn",
				Label:      a.Name,
				OperatorID: a.OperatorID,
				Attachment: att,
			}
		}
	}
	if p, ok := st.lookupLocalPrefix(addr); ok {
		role := normalizeKind(p.Role, "customer")
		return endpointClass{
			ASN:         asn,
			Scope:       endpointScopeFromNetworkRole(role),
			Source:      "prefix",
			NetworkName: p.Name,
			NetworkRole: role,
			Label:       p.Name,
			OperatorID:  p.OperatorID,
			Attachment:  att,
		}
	}
	return endpointClass{
		ASN:        asn,
		Scope:      "remote",
		Source:     "fallback",
		Attachment: att,
	}
}

func (st *classifierState) lookupAttachment(vlan uint16) attachmentClass {
	if vlan == 0 {
		return attachmentClass{Kind: "unknown", Boundary: "unknown"}
	}
	if v, ok := st.vlans[vlan]; ok {
		return attachmentClass{
			Kind:       v.AttachmentKind,
			Boundary:   v.AttachmentBoundary,
			Label:      v.Label,
			OperatorID: v.OperatorID,
		}
	}
	return attachmentClass{Kind: "unknown", Boundary: "unknown"}
}

func (st *classifierState) lookupASN(addr netip.Addr) uint32 {
	if addr.Is4() {
		if p, ok := st.bgp4.Lookup(addr); ok {
			return p.ASN
		}
		return 0
	}
	if p, ok := st.bgp6.Lookup(addr); ok {
		return p.ASN
	}
	return 0
}

func (st *classifierState) lookupLocalPrefix(addr netip.Addr) (prefixClass, bool) {
	if addr.Is4() {
		return st.local4.Lookup(addr)
	}
	return st.local6.Lookup(addr)
}

func deriveDirection(hasLocalConfig bool, src, dst endpointClass) string {
	if !hasLocalConfig {
		return "out"
	}
	if src.Scope == "unknown" || dst.Scope == "unknown" {
		return "unknown"
	}
	srcLocal := isLocalEndpointScope(src.Scope)
	dstLocal := isLocalEndpointScope(dst.Scope)
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

func normalizeKind(kind, fallback string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		return fallback
	}
	return kind
}

func normalizeBoundary(boundary, attachmentKind string) string {
	boundary = strings.ToLower(strings.TrimSpace(boundary))
	switch boundary {
	case "internal", "external", "unknown":
		return boundary
	case "":
		// derive a safe default from attachment kind for older rows where only
		// `kind` existed in vlan_map.
	default:
		return "unknown"
	}
	if isLocalAttachmentKind(attachmentKind) {
		return "internal"
	}
	switch normalizeKind(attachmentKind, "unknown") {
	case "uplink", "ix", "peering", "transit", "pni", "ppni":
		return "external"
	default:
		return "unknown"
	}
}

func isLocalAttachmentKind(kind string) bool {
	switch normalizeKind(kind, "unknown") {
	case "local", "customer", "internal", "mgmt":
		return true
	default:
		return false
	}
}

func endpointScopeFromNetworkRole(role string) string {
	switch normalizeKind(role, "customer") {
	case "customer":
		return "customer"
	case "local", "internal", "mgmt":
		return "local"
	default:
		return "customer"
	}
}

func isLocalEndpointScope(scope string) bool {
	switch normalizeKind(scope, "unknown") {
	case "local", "customer":
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
