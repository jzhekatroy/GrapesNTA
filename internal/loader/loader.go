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

// Options controls the BPF collection load. Zero-value is safe and equivalent
// to previous behavior (XDP_PASS for accounted packets).
type Options struct {
	// XDPFinalAction overrides the `xdp_final_action` const in the BPF program.
	// Valid values: 2 = XDP_PASS (safe, default), 1 = XDP_DROP (SPAN/mirror only).
	// 0 means "leave as compiled-in default".
	XDPFinalAction uint32
}

// LoadObjects loads an eBPF collection from a compiled ELF path (e.g. bpf/xdp_flow.o)
// with default options.
func LoadObjects(bpfObjPath string) (*Objects, error) {
	return LoadObjectsWithOptions(bpfObjPath, Options{})
}

// LoadObjectsWithOptions loads the ELF and, when opts contains non-zero overrides,
// rewrites the corresponding `const volatile` globals before instantiating the
// collection.
func LoadObjectsWithOptions(bpfObjPath string, opts Options) (*Objects, error) {
	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		return nil, fmt.Errorf("load spec %q: %w", bpfObjPath, err)
	}

	if opts.XDPFinalAction != 0 {
		if err := spec.RewriteConstants(map[string]interface{}{
			"xdp_final_action": opts.XDPFinalAction,
		}); err != nil {
			return nil, fmt.Errorf("rewrite xdp_final_action=%d: %w", opts.XDPFinalAction, err)
		}
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
