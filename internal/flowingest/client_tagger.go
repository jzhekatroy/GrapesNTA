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

// DefaultClientPrefixesTable is the operator-managed view of enabled client
// networks. Clients bound by equipment ports are absent from it by design:
// resolving those needs a sampler address and an ifIndex, which a DNS packet
// does not carry.
const DefaultClientPrefixesTable = "default.net_client_prefixes_enabled"

// ClientTaggerConfig wires the tagger to the client catalog. Enabled=false or an
// empty Table disables tagging entirely.
type ClientTaggerConfig struct {
	Enabled bool
	DSN     string
	Refresh time.Duration
	Table   string
}

// ClientTaggerStats reports what the tagger has done since process start.
// Prefixes=0 with a growing Untagged is the signature of a catalog that never
// loaded, which otherwise looks exactly like a client with no traffic.
type ClientTaggerStats struct {
	Prefixes int
	Tagged   uint64
	Untagged uint64
}

type clientTaggerState struct {
	v4       *ipTrie
	v6       *ipTrie
	prefixes int
}

// ClientTagger answers which cabinet client owns an address. TrafficClassifier
// can do the same through AttachClients, but it also reloads the BGP, ASN, L3
// and VLAN catalogs on every refresh; a collector that needs nothing but the
// client would pay for all of that in memory and in queries. A nil tagger is a
// no-op, so callers can wire it unconditionally.
type ClientTagger struct {
	log    *slog.Logger
	conn   chdriver.Conn
	cfg    ClientTaggerConfig
	cancel context.CancelFunc
	state  atomic.Pointer[clientTaggerState]

	tagged   atomic.Uint64
	untagged atomic.Uint64
}

// NewClientTagger returns nil when tagging is off. A load failure never blocks
// startup: capturing DNS matters more than knowing whose it is, and the tagger
// keeps returning no client until a refresh succeeds.
func NewClientTagger(ctx context.Context, log *slog.Logger, cfg ClientTaggerConfig) (*ClientTagger, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	cfg.Table = strings.TrimSpace(cfg.Table)
	if cfg.Table == "" {
		cfg.Table = DefaultClientPrefixesTable
	}
	if strings.TrimSpace(cfg.DSN) == "" {
		return nil, fmt.Errorf("client tagging requires -ch-dsn")
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
		return nil, fmt.Errorf("client tagging clickhouse open: %w", err)
	}
	tctx, cancel := context.WithCancel(ctx)
	t := &ClientTagger{log: log, conn: conn, cfg: cfg, cancel: cancel}
	t.state.Store(emptyClientTaggerState())
	if err := t.refreshOnce(tctx); err != nil {
		log.Warn("client prefixes initial load failed; starting with no clients",
			"table", cfg.Table, "err", err)
	}
	go t.run(tctx)
	log.Info("client tagging enabled", "table", cfg.Table, "refresh", cfg.Refresh)
	return t, nil
}

func (t *ClientTagger) Close() {
	if t == nil {
		return
	}
	t.cancel()
	if t.conn != nil {
		_ = t.conn.Close()
	}
}

func (t *ClientTagger) run(ctx context.Context) {
	ticker := time.NewTicker(t.cfg.Refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := t.refreshOnce(ctx); err != nil {
				t.log.Warn("client prefixes refresh failed", "table", t.cfg.Table, "err", err)
			}
		}
	}
}

func emptyClientTaggerState() *clientTaggerState {
	return &clientTaggerState{v4: newIPTrie(), v6: newIPTrie()}
}

// refreshOnce swaps in a whole new state or leaves the old one alone: a partial
// catalog would silently unassign clients whose rows failed to read.
func (t *ClientTagger) refreshOnce(ctx context.Context) error {
	rows, err := t.conn.Query(ctx, "SELECT client_id, prefix, family FROM "+t.cfg.Table)
	if err != nil {
		return fmt.Errorf("load client prefixes: %w", err)
	}
	defer rows.Close()

	st := emptyClientTaggerState()
	for rows.Next() {
		var clientID, prefix string
		var family uint8
		if err := rows.Scan(&clientID, &prefix, &family); err != nil {
			return fmt.Errorf("scan client prefixes: %w", err)
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
			st.v4.Insert(p.Masked(), pc)
		} else {
			st.v6.Insert(p.Masked(), pc)
		}
		st.prefixes++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read client prefixes: %w", err)
	}
	t.state.Store(st)
	return nil
}

// ClientForIP returns the owning client id, or an empty string when the address
// belongs to nobody registered. raw holds an IPv4 address in its first four
// bytes and an IPv6 address in all sixteen, matching how both the flow rows and
// the DNS rows carry addresses.
func (t *ClientTagger) ClientForIP(raw [16]byte, ipVersion uint8) string {
	if t == nil {
		return ""
	}
	st := t.state.Load()
	if st == nil {
		return ""
	}
	addr, ok := addrFromFlow(raw, ipVersion)
	if !ok {
		t.untagged.Add(1)
		return ""
	}
	trie := st.v4
	if !addr.Is4() {
		trie = st.v6
	}
	if pc, found := trie.Lookup(addr); found && pc.EntityID != "" {
		t.tagged.Add(1)
		return pc.EntityID
	}
	t.untagged.Add(1)
	return ""
}

func (t *ClientTagger) Stats() ClientTaggerStats {
	if t == nil {
		return ClientTaggerStats{}
	}
	prefixes := 0
	if st := t.state.Load(); st != nil {
		prefixes = st.prefixes
	}
	return ClientTaggerStats{
		Prefixes: prefixes,
		Tagged:   t.tagged.Load(),
		Untagged: t.untagged.Load(),
	}
}
