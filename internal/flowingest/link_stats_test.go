package flowingest

import "testing"

func TestLinkStatsFromTableMlx5(t *testing.T) {
	table := map[string]uint64{
		"rx_packets_phy":  2306354,
		"rx_discards_phy": 27,
		"rx_packets":      1200,
		"rx_dropped":      99,
	}
	got, ok := linkStatsFromTable(table, nil, nil)
	if !ok {
		t.Fatal("expected mlx5 counters to be recognised")
	}
	if got.RxPackets != 2306354 || got.RxDiscards != 27 {
		t.Fatalf("wrong counters picked: %+v", got)
	}
	if got.Source != "ethtool:rx_packets_phy+rx_discards_phy" {
		t.Fatalf("unexpected source %q", got.Source)
	}
}

func TestLinkStatsFromTablePrefersFirstCandidate(t *testing.T) {
	// Both names present: priority order decides, so a NIC exposing a generic
	// alias next to the phy counter does not get the smaller number.
	table := map[string]uint64{
		"rx_missed_errors": 5,
		"rx_discards_phy":  41,
		"rx_packets_phy":   100,
	}
	got, _ := linkStatsFromTable(table, nil, nil)
	if got.RxDiscards != 41 {
		t.Fatalf("expected rx_discards_phy to win, got %d", got.RxDiscards)
	}
}

func TestLinkStatsFromTableOverride(t *testing.T) {
	table := map[string]uint64{"custom_in": 7, "custom_lost": 3}
	got, ok := linkStatsFromTable(table, []string{"custom_in"}, []string{"custom_lost"})
	if !ok || got.RxPackets != 7 || got.RxDiscards != 3 {
		t.Fatalf("override ignored: ok=%v stats=%+v", ok, got)
	}
}

func TestLinkStatsFromTableUnknownDriver(t *testing.T) {
	// An unreadable NIC must stay unreadable rather than reporting zero loss.
	table := map[string]uint64{"tx_packets": 10, "collisions": 0}
	if _, ok := linkStatsFromTable(table, nil, nil); ok {
		t.Fatal("expected no match for a table without any known rx counter")
	}
	if _, ok := linkStatsFromTable(nil, nil, nil); ok {
		t.Fatal("expected no match for an empty table")
	}
}

func TestLinkStatsFromTablePartialMatch(t *testing.T) {
	// Discards present, packets absent: still worth reporting, and the source
	// says exactly which half we have.
	table := map[string]uint64{"rx_discards_phy": 12}
	got, ok := linkStatsFromTable(table, nil, nil)
	if !ok {
		t.Fatal("expected a partial match to count")
	}
	if got.Source != "ethtool:rx_discards_phy" {
		t.Fatalf("unexpected source %q", got.Source)
	}
}
