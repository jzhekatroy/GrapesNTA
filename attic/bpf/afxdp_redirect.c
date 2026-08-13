// SPDX-License-Identifier: GPL-2.0
/*
 * afxdp_redirect.c — minimal XDP for AF_XDP bring-up.
 *
 * Step 1 (this file): compiles, attaches as XDP_PASS for wiring tests.
 * Step 2: add BPF_MAP_TYPE_XSKMAP `xsks_map` and return bpf_redirect_map
 *   (&xsks_map, ctx->rx_queue_index, 0) after userspace binds an AF_XDP fd per queue.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_afxdp_entry(struct xdp_md *ctx)
{
	(void)ctx;
	return XDP_PASS; /* TODO: bpf_redirect_map to xsks_map for production */
}
