package afxdp

// XSKReader is the interface for a single AF_XDP socket + UMEM (one RX queue).
// Implementation will use linux syscalls, cilium/ebpf, or cgo+libxdp — TBD.
type XSKReader interface {
	// Start binds UMEM, creates socket, sets BPF map slot for this queue, blocks in recv loop.
	Start() error
	Stop() error
}
