package main

import (
	"xdpflowd/internal/flowingest"
)

// newFlowKVExcluder adapts the shared exclusion engine to the BPF-native flow
// key. It is installed on the FlowDrainer, so a single evaluation covers both
// the ClickHouse rows and the NetFlow v9 records built from the same chunk.
//
// The returned slice is a copy as soon as anything is dropped: the legacy drain
// paths reuse the original chunk to issue their follow-up deletes, so compacting
// it in place would leave excluded entries stuck in the BPF map.
func newFlowKVExcluder(excl *flowingest.ExclusionFilter, sourceID string, sampler [16]byte) func([]flowKV) []flowKV {
	if excl == nil {
		return nil
	}
	return func(chunk []flowKV) []flowKV {
		var kept []flowKV
		for i := range chunk {
			m := exclusionMatchFromKV(&chunk[i], sourceID, sampler)
			if !excl.Excluded(&m) {
				if kept != nil {
					kept = append(kept, chunk[i])
				}
				continue
			}
			excl.Count(chunk[i].v.Packets, chunk[i].v.Bytes)
			if kept == nil {
				kept = make([]flowKV, i, len(chunk))
				copy(kept, chunk[:i])
			}
		}
		if kept == nil {
			return chunk
		}
		return kept
	}
}

func exclusionMatchFromKV(fv *flowKV, sourceID string, sampler [16]byte) flowingest.ExclusionMatch {
	return flowingest.ExclusionMatch{
		SrcAddr:   fv.k.SrcAddr,
		DstAddr:   fv.k.DstAddr,
		IPVersion: fv.k.IPVersion,
		Proto:     fv.k.Proto,
		SrcPort:   keyPortHost(fv.k.SrcPort),
		DstPort:   keyPortHost(fv.k.DstPort),
		SrcVLAN:   fv.k.VLANID,
		DstVLAN:   fv.k.VLANID,
		Sampler:   sampler,
		SourceID:  sourceID,
	}
}
