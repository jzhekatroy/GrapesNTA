// Package loader loads the compiled eBPF ELF (bpf/xdp_flow.o) into the kernel.
// Build the object on Linux: see Makefile target bpf/xdp_flow.o (clang -target bpf).
package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Objects holds handles to the XDP program and BPF maps produced from bpf/xdp_flow.c.
type Objects struct {
	coll *ebpf.Collection

	XdpFlowProg *ebpf.Program
	Flows       *ebpf.Map
	Stats       *ebpf.Map
}

// LoadObjects loads an eBPF collection from a compiled ELF path (e.g. bpf/xdp_flow.o).
func LoadObjects(bpfObjPath string) (*Objects, error) {
	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		return nil, fmt.Errorf("load spec %q: %w", bpfObjPath, err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}

	prog, ok := coll.Programs["xdp_flow_prog"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("program xdp_flow_prog not found in %s", bpfObjPath)
	}
	flows, ok := coll.Maps["flows"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("map flows not found")
	}
	stats, ok := coll.Maps["stats"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("map stats not found")
	}

	return &Objects{
		coll:        coll,
		XdpFlowProg: prog,
		Flows:       flows,
		Stats:       stats,
	}, nil
}

// Close releases kernel resources.
func (o *Objects) Close() {
	if o.coll != nil {
		o.coll.Close()
		o.coll = nil
	}
}
