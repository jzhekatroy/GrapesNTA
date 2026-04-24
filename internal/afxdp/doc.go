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
package afxdp
