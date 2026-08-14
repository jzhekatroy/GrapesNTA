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

	// DirectionSettings and InterfaceRoles drive port-based direction. Empty
	// values disable the feature: the classifier then always derives direction
	// from prefixes, which keeps installations without the interface-roles DDL
	// working.
	DirectionSettings string
	InterfaceRoles    string

	// ClientPrefixes / ClientPorts feed cabinet-client tagging (src_client /
	// dst_client). Empty disables the corresponding loader so older installs
	// keep working before the net_clients DDL is applied.
	ClientPrefixes string
	ClientPorts    string
}

// Direction modes stored in net_direction_settings.direction_mode.
const (
	DirectionModePrefixes = "prefixes"
	DirectionModePorts    = "ports"

	// directionSettingsID is the single settings row written by NTAdmin.
	directionSettingsID = "global"
)

// How to read a flow whose both endpoints are missing from the L3 catalog,
// stored in net_direction_settings.unknown_networks.
const (
	// UnknownNetworksForeign assumes anything not catalogued belongs to
	// somebody else, so such a flow is transit. Historical behaviour.
	UnknownNetworksForeign = "foreign"
	// UnknownNetworksUnclassified refuses to guess: transit then requires both
	// networks to be present in the catalog, and everything else is reported
	// as a gap in the markup.
	UnknownNetworksUnclassified = "unclassified"
)

// DirectionUnknown is the existing "we could not tell" bucket. Rollups filter
// on a fixed direction list and the UI already renders this value, so an
// undescribed pair reuses it instead of introducing a value that would drop
// out of every aggregate. src_endpoint_source still distinguishes a missing
// prefix from a classifier that never ran.
const DirectionUnknown = "unknown"

// endpointSourcePrefix marks an endpoint resolved through net_l3_prefixes —
// i.e. a network somebody deliberately described, ours or foreign.
const endpointSourcePrefix = "prefix"

// Port sides as marked by the operator. Ports missing from the map have no
// known side, which always yields an unknown direction.
const (
	portSideInternal uint8 = 1
	portSideExternal uint8 = 2
)

type portKey struct {
	sampler [16]byte
	ifIndex uint32
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

	portsClassified atomic.Uint64
	portsNoIfIndex  atomic.Uint64
	portsUnmarked   atomic.Uint64

	// Flows left unclassified because neither network is described. Growth
	// here is the signal to go and fill in the L3 catalog.
	networksUnclassified atomic.Uint64
}

type classifierState struct {
	bgp4 *ipTrie
	bgp6 *ipTrie
	asn4 *ipTrie
	asn6 *ipTrie
	l3v4 *ipTrie
	l3v6 *ipTrie

	// Cabinet clients: prefix -> client_id (EntityID slot) and port -> client_id.
	client4    *ipTrie
	client6    *ipTrie
	clientPorts map[portKey]string

	vlans map[uint16]vlanClass

	directionMode   string
	unknownNetworks string
	portSides       map[portKey]uint8

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
	if strings.TrimSpace(t.ClientPrefixes) == "" {
		t.ClientPrefixes = "default.net_client_prefixes_enabled"
	}
	if strings.TrimSpace(t.ClientPorts) == "" {
		t.ClientPorts = "default.net_client_ports_enabled"
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
		bgp4:            newIPTrie(),
		bgp6:            newIPTrie(),
		asn4:            newIPTrie(),
		asn6:            newIPTrie(),
		l3v4:            newIPTrie(),
		l3v6:            newIPTrie(),
		client4:         newIPTrie(),
		client6:         newIPTrie(),
		clientPorts:     make(map[portKey]string),
		vlans:           make(map[uint16]vlanClass),
		directionMode:   DirectionModePrefixes,
		unknownNetworks: UnknownNetworksForeign,
		portSides:       make(map[portKey]uint8),
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
	// Port-based direction is loaded last and never fails the refresh: an
	// installation may simply lack the interface-roles tables. A ClickHouse
	// outage is already caught by the loaders above, which keep the previous
	// state in place.
	tc.loadDirectionMode(ctx, st)
	tc.loadUnknownNetworksPolicy(ctx, st)
	portSwitches := tc.loadPortSides(ctx, st)
	clientPrefixRows := tc.loadClientPrefixes(ctx, st)
	clientPortRows := tc.loadClientPorts(ctx, st)
	st.hasLocalConfig = l3Rows > 0
	tc.state.Store(st)
	tc.log.Info("traffic classifier refreshed",
		"bgp_prefixes", bgpRows,
		"ip_asn_prefixes", ipASNRows,
		"l3_prefixes", l3Rows,
		"vlans", vlanRows,
		"internal_vlans", internalVLANs,
		"has_local_config", st.hasLocalConfig,
		"direction_mode", st.directionMode,
		"unknown_networks", st.unknownNetworks,
		"direction_networks_unclassified", tc.networksUnclassified.Load(),
		"port_sides", len(st.portSides),
		"port_switches", portSwitches,
		"client_prefixes", clientPrefixRows,
		"client_ports", clientPortRows,
		"direction_ports_classified", tc.portsClassified.Load(),
		"direction_ports_no_ifindex", tc.portsNoIfIndex.Load(),
		"direction_ports_unmarked", tc.portsUnmarked.Load(),
		"elapsed", time.Since(start),
	)
	if st.directionMode == DirectionModePorts && len(st.portSides) == 0 {
		tc.log.Warn("direction mode is ports but no port sides are marked: every flow will be unclassified",
			"interface_roles_table", tc.cfg.Tables.InterfaceRoles,
		)
	}
	if st.unknownNetworks == UnknownNetworksUnclassified && l3Rows == 0 {
		tc.log.Warn("unknown networks are marked unclassified but the L3 catalog is empty: every flow will be unclassified",
			"l3_prefixes_table", tc.cfg.Tables.L3Prefixes,
		)
	}
	return nil
}

// loadDirectionMode reads the single settings row. Any problem leaves the
// prefix mode in place: switching direction models must be an explicit,
// readable decision, never a side effect of a missing table.
func (tc *TrafficClassifier) loadDirectionMode(ctx context.Context, st *classifierState) {
	table := strings.TrimSpace(tc.cfg.Tables.DirectionSettings)
	if table == "" {
		return
	}
	rows, err := tc.conn.Query(ctx,
		"SELECT direction_mode FROM "+table+" WHERE settings_id = '"+directionSettingsID+"' LIMIT 1")
	if err != nil {
		tc.log.Warn("load direction settings", "table", table, "err", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var mode string
		if err := rows.Scan(&mode); err != nil {
			tc.log.Warn("scan direction settings", "table", table, "err", err)
			return
		}
		if strings.ToLower(strings.TrimSpace(mode)) == DirectionModePorts {
			st.directionMode = DirectionModePorts
		}
	}
	if err := rows.Err(); err != nil {
		tc.log.Warn("read direction settings", "table", table, "err", err)
	}
}

// loadUnknownNetworksPolicy reads the setting in its own query: installations
// upgraded from before the column exists must keep reading direction_mode,
// which a combined SELECT would break.
func (tc *TrafficClassifier) loadUnknownNetworksPolicy(ctx context.Context, st *classifierState) {
	table := strings.TrimSpace(tc.cfg.Tables.DirectionSettings)
	if table == "" {
		return
	}
	rows, err := tc.conn.Query(ctx,
		"SELECT unknown_networks FROM "+table+" WHERE settings_id = '"+directionSettingsID+"' LIMIT 1")
	if err != nil {
		// Missing column on an older schema: keep the historical behaviour.
		tc.log.Warn("load unknown networks policy", "table", table, "err", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var policy string
		if err := rows.Scan(&policy); err != nil {
			tc.log.Warn("scan unknown networks policy", "table", table, "err", err)
			return
		}
		if strings.ToLower(strings.TrimSpace(policy)) == UnknownNetworksUnclassified {
			st.unknownNetworks = UnknownNetworksUnclassified
		}
	}
	if err := rows.Err(); err != nil {
		tc.log.Warn("read unknown networks policy", "table", table, "err", err)
	}
}

// loadPortSides fills the manual port marking map and returns the number of
// distinct switches it covers.
func (tc *TrafficClassifier) loadPortSides(ctx context.Context, st *classifierState) int {
	table := strings.TrimSpace(tc.cfg.Tables.InterfaceRoles)
	if table == "" {
		return 0
	}
	rows, err := tc.conn.Query(ctx,
		"SELECT switch_ip, if_index, boundary FROM "+table+" WHERE boundary IN ('internal', 'external')")
	if err != nil {
		tc.log.Warn("load interface roles", "table", table, "err", err)
		return 0
	}
	defer rows.Close()
	switches := make(map[[16]byte]struct{})
	skipped := 0
	for rows.Next() {
		var switchIP, boundary string
		var ifIndex uint32
		if err := rows.Scan(&switchIP, &ifIndex, &boundary); err != nil {
			tc.log.Warn("scan interface roles", "table", table, "err", err)
			return len(switches)
		}
		// switch_ip in the catalog is the sampler address of the exporter, so
		// the same encoding as FlowRow.SamplerAddress makes the hot path a
		// plain map lookup.
		sampler, err := ParseSamplerAddress(switchIP)
		if err != nil || sampler == ([16]byte{}) || ifIndex == 0 {
			skipped++
			continue
		}
		var side uint8
		switch strings.ToLower(strings.TrimSpace(boundary)) {
		case "internal":
			side = portSideInternal
		case "external":
			side = portSideExternal
		default:
			skipped++
			continue
		}
		st.portSides[portKey{sampler: sampler, ifIndex: ifIndex}] = side
		switches[sampler] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		tc.log.Warn("read interface roles", "table", table, "err", err)
	}
	if skipped > 0 {
		tc.log.Warn("interface roles rows skipped", "table", table, "rows", skipped)
	}
	return len(switches)
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
		// Default-on: a fresh box may not have loaded iptoasn yet. Do not
		// fail the whole classifier (that exits flowcollectord).
		tc.log.Warn("IP ASN fallback unavailable", "table", tc.cfg.Tables.IPASNPrefixes, "err", err)
		return 0, nil
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

// loadClientPrefixes fills the cabinet-client prefix tries. Failures are
// non-fatal: tagging simply stays empty until the next successful refresh.
func (tc *TrafficClassifier) loadClientPrefixes(ctx context.Context, st *classifierState) int {
	table := strings.TrimSpace(tc.cfg.Tables.ClientPrefixes)
	if table == "" {
		return 0
	}
	rows, err := tc.conn.Query(ctx, "SELECT client_id, prefix, family FROM "+table)
	if err != nil {
		tc.log.Warn("load client prefixes", "table", table, "err", err)
		return 0
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var clientID, prefix string
		var family uint8
		if err := rows.Scan(&clientID, &prefix, &family); err != nil {
			tc.log.Warn("scan client prefixes", "table", table, "err", err)
			return n
		}
		clientID = strings.TrimSpace(clientID)
		if clientID == "" {
			continue
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(prefix))
		if err != nil || !p.IsValid() {
			continue
		}
		pc := prefixClass{EntityID: clientID}
		if family == 4 || p.Addr().Is4() {
			st.client4.Insert(p.Masked(), pc)
		} else {
			st.client6.Insert(p.Masked(), pc)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		tc.log.Warn("read client prefixes", "table", table, "err", err)
	}
	return n
}

// loadClientPorts fills the cabinet-client port map (sampler + ifIndex).
func (tc *TrafficClassifier) loadClientPorts(ctx context.Context, st *classifierState) int {
	table := strings.TrimSpace(tc.cfg.Tables.ClientPorts)
	if table == "" {
		return 0
	}
	rows, err := tc.conn.Query(ctx, "SELECT client_id, switch_ip, if_index FROM "+table)
	if err != nil {
		tc.log.Warn("load client ports", "table", table, "err", err)
		return 0
	}
	defer rows.Close()
	n := 0
	skipped := 0
	for rows.Next() {
		var clientID, switchIP string
		var ifIndex uint32
		if err := rows.Scan(&clientID, &switchIP, &ifIndex); err != nil {
			tc.log.Warn("scan client ports", "table", table, "err", err)
			return n
		}
		clientID = strings.TrimSpace(clientID)
		sampler, err := ParseSamplerAddress(switchIP)
		if err != nil || clientID == "" || sampler == ([16]byte{}) || ifIndex == 0 {
			skipped++
			continue
		}
		st.clientPorts[portKey{sampler: sampler, ifIndex: ifIndex}] = clientID
		n++
	}
	if err := rows.Err(); err != nil {
		tc.log.Warn("read client ports", "table", table, "err", err)
	}
	if skipped > 0 {
		tc.log.Warn("client ports rows skipped", "table", table, "rows", skipped)
	}
	return n
}

func (st *classifierState) lookupClientPrefix(addr netip.Addr) string {
	if st == nil || !addr.IsValid() {
		return ""
	}
	var trie *ipTrie
	if addr.Is4() {
		trie = st.client4
	} else {
		trie = st.client6
	}
	if pc, ok := trie.Lookup(addr); ok {
		return pc.EntityID
	}
	return ""
}

// AttachClients sets src_client / dst_client on a flow row.
// Prefix match wins; if empty, ingress ifIndex -> src, egress ifIndex -> dst.
func (tc *TrafficClassifier) AttachClients(r *FlowRow) {
	if tc == nil || r == nil {
		return
	}
	st := tc.state.Load()
	if st == nil {
		return
	}
	ipVersion := IPVersionFromEtype(r.Etype)
	if srcAddr, ok := addrFromFlow(r.SrcAddr, ipVersion); ok {
		if id := st.lookupClientPrefix(srcAddr); id != "" {
			r.SrcClient = id
		}
	}
	if dstAddr, ok := addrFromFlow(r.DstAddr, ipVersion); ok {
		if id := st.lookupClientPrefix(dstAddr); id != "" {
			r.DstClient = id
		}
	}
	if r.SrcClient == "" && r.InIf != 0 {
		if id, ok := st.clientPorts[portKey{sampler: r.SamplerAddress, ifIndex: r.InIf}]; ok {
			r.SrcClient = id
		}
	}
	if r.DstClient == "" && r.OutIf != 0 {
		if id, ok := st.clientPorts[portKey{sampler: r.SamplerAddress, ifIndex: r.OutIf}]; ok {
			r.DstClient = id
		}
	}
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
	direction := DeriveDirection(srcClass, dstClass, st.unknownNetworks)
	if direction == DirectionUnknown {
		tc.networksUnclassified.Add(1)
	}
	return srcClass, dstClass, direction
}

// DirectionMode reports the active direction model.
func (tc *TrafficClassifier) DirectionMode() string {
	if tc == nil {
		return DirectionModePrefixes
	}
	st := tc.state.Load()
	if st == nil || st.directionMode == "" {
		return DirectionModePrefixes
	}
	return st.directionMode
}

// PortDirection derives direction from the manually marked sides of the
// ingress and egress ports. The second result is false in prefix mode, which
// tells the caller to keep the prefix-derived direction.
//
// The model is strict: if either side is unknown - the port is unmarked or the
// flow carries no ifIndex - the direction is unknown rather than guessed.
func (tc *TrafficClassifier) PortDirection(sampler [16]byte, inIf, outIf uint32) (string, bool) {
	if tc == nil {
		return "", false
	}
	st := tc.state.Load()
	if st == nil || st.directionMode != DirectionModePorts {
		return "", false
	}
	if inIf == 0 || outIf == 0 {
		tc.portsNoIfIndex.Add(1)
		return "unknown", true
	}
	inSide := st.portSides[portKey{sampler: sampler, ifIndex: inIf}]
	outSide := st.portSides[portKey{sampler: sampler, ifIndex: outIf}]
	if inSide == 0 || outSide == 0 {
		tc.portsUnmarked.Add(1)
		return "unknown", true
	}
	tc.portsClassified.Add(1)
	switch {
	case inSide == portSideExternal && outSide == portSideInternal:
		return "in", true
	case inSide == portSideInternal && outSide == portSideExternal:
		return "out", true
	case inSide == portSideInternal && outSide == portSideInternal:
		return "internal", true
	default:
		return "transit", true
	}
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
			Source:      endpointSourcePrefix,
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
//
// With one end inside our networks the direction is unambiguous and the other
// end needs no markup. When neither end is ours the answer depends on how much
// we actually know: an address absent from net_l3_prefixes is not "somebody
// else's", it is simply undescribed, and calling that transit hides forgotten
// prefixes of our own inside a meaningful category. Under
// UnknownNetworksUnclassified transit therefore requires both networks to be
// catalogued — a deliberate statement by the operator; unknownNetworks
// defaults to the historical UnknownNetworksForeign.
func DeriveDirection(src, dst EndpointClass, unknownNetworks string) string {
	srcLocal := isLocalOrCustomerRole(src.Role)
	dstLocal := isLocalOrCustomerRole(dst.Role)
	switch {
	case srcLocal && dstLocal:
		return "internal"
	case srcLocal:
		return "out"
	case dstLocal:
		return "in"
	}
	if unknownNetworks != UnknownNetworksUnclassified || (isCatalogued(src) && isCatalogued(dst)) {
		return "transit"
	}
	return DirectionUnknown
}

// isCatalogued reports whether the endpoint matched a described network rather
// than falling through to the default remote role.
func isCatalogued(c EndpointClass) bool {
	return c.Source == endpointSourcePrefix
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
