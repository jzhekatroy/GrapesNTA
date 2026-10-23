package flowingest

import "testing"

func TestEnrichedInsertArgsIxColumns(t *testing.T) {
	r := sampleFullRow()
	without := enrichedInsertArgs(nil, &r, false)
	with := enrichedInsertArgs(nil, &r, true)
	if len(with) != len(without)+2 {
		t.Fatalf("IX args = %d, plain args = %d", len(with), len(without))
	}
	// src_client and dst_client sit right before the IX pair.
	idx := -1
	for i, v := range with {
		if s, ok := v.(string); ok && s == r.DstClient {
			idx = i
			break
		}
	}
	if idx < 0 || with[idx+1] != r.IxSrcClient || with[idx+2] != r.IxDstClient {
		t.Fatalf("IX columns not after dst_client: idx=%d", idx)
	}
	if without[idx+1] != r.SrcVLAN {
		t.Fatalf("plain row must go straight to src_vlan, got %v", without[idx+1])
	}
}

func TestRowsHaveIxClients(t *testing.T) {
	if RowsHaveIxClients([]FlowRow{{SrcClient: "a", DstClient: "b"}}) {
		t.Fatal("port tags alone must keep the old column list")
	}
	if !RowsHaveIxClients([]FlowRow{{}, {IxDstClient: "80249"}}) {
		t.Fatal("one IX row must switch the batch to IX columns")
	}
}
