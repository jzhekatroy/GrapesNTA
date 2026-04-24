// Package afxdp is the future AF_XDP dataplane for high-throughput flow export.
// It is developed on branch feature/afxdp, separate from the eBPF per-packet
// + map aggregation path in cmd/xdpflowd.
//
// # Performance design constraints (intentional)
//
//  - One AF_XDP socket (and UMEM) per hardware RX queue; pin each worker CPU.
//  - UMEM: prefer huge pages, preallocated packet buffers; no per-packet heap allocs
//    on the hot path.
//  - XDP program: minimal — bind queue to xsk (redirect); heavy parsing in userspace
//    or a tiny BPF helper if we need early filtering.
//  - Hot receive loop: C or Rust first-class; if Go, strict no-alloc batch recv and
//    sync.Pool for scratch only — measure before committing.
//  - Target OS: kernel 6.1+ (LTS) for mature AF_XDP + driver behaviour; final validation
//    on the same mlx4 class NIC as production (VM virtio is dev-only).
//
// # Workflow
//
//  - Tag on main: baseline before AF_XDP (e.g. v0.2.0-baseline).
//  - Debug on VM (functional); load / fifo / CPU tests on the real server.
//
// # Repository layout (this effort)
//
//  cmd/
//    xdpflowd/          — current production path: eBPF map + userspace read (unchanged on main)
//    afxdpflowd/        — new entrypoint: UMEM, xsk rings, workers; reuses netflow export
//  internal/
//    afxdp/             — config, xsk/UMEM glue (Go); optional cgo to libxdp or raw syscalls
//    loader/            — existing BPF loader; afxdp may add second Program for xsks map
//    netv9/             — (phase 2) move NetFlow v9 encoder from cmd/xdpflowd/netflow.go
//  bpf/
//    xdp_flow.c         — existing flow map program (v0.2.0-baseline)
//    afxdp_redirect.c  — tiny XDP: bpf_redirect to AF_XDP socket map (per queue)
//  bin/
//    xdpflowd           — make build
//    afxdpflowd         — make build-afxdp (github.com/planktonzp/xdp: libbpf-style xsks map + AF_XDP)
//
//  Wire ground truth (JSON on stderr) is for scripts/afxdp_wire_accuracy.sh vs /sys/class/net/.../statistics.
//
// # Why cmd/afxdpflowd instead of one binary
//
//  - Smaller change risk: xdpflowd stays the known-good eBPF+map path.
//  - afxdpflowd can link cgo / static libs without touching the map daemon.
//  - Ops can run either binary per host until cutover.
package afxdp
