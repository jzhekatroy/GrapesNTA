// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_light.c — diagnostic XDP program for isolating mlx4_en native XDP cost.
 *
 * Symbol contract is identical to bpf/xdp_flow.c so that the same userspace
 * loader (internal/loader.LoadObjectsWithOptions) and the same `xdpflowd`
 * binary can attach it via `-bpf bpf/xdp_light.o`. Used to answer:
 *
 *     If we replace the full flow-tracking program with a near-zero-cost one,
 *     does mlx4_en native XDP still degrade RX (rx_fifo_errors, rx_packets)?
 *
 * What this program does:
 *   - Bumps stats[0] (total_packets) once per packet via a PERCPU array.
 *   - Returns xdp_final_action (XDP_PASS by default, can be rewritten to XDP_DROP).
 *
 * What this program intentionally does NOT do:
 *   - No L2/L3/L4 parsing.
 *   - No bounds checks for headers (we never touch packet bytes here).
 *   - No flow_key / flow_value computation.
 *   - No HASH map lookup or update.
 *   - No timestamps via bpf_ktime_get_ns().
 *
 * Therefore any RX degradation observed when this program is attached must
 * come from the XDP path inside the driver / kernel itself, not from BPF
 * work. That is the whole point of the diagnostic.
 *
 * Loader compatibility notes:
 *   - SEC name and program name must stay "xdp" / "xdp_flow_prog" because
 *     internal/loader looks them up by name.
 *   - Maps "flows" and "stats" must exist so that loader does not fail.
 *     We make `flows` a 1-entry HASH so it is essentially free.
 *   - `xdp_final_action` const stays so that `-xdp-action pass|drop` keeps
 *     working without code changes in xdpflowd.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * xdp_final_action — rewritten by userspace via RewriteConstants:
 *   2 = XDP_PASS (default), 1 = XDP_DROP.
 */
const volatile __u32 xdp_final_action = XDP_PASS;

/*
 * Minimal flow_key / flow_value placeholders. They must define the same map
 * names "flows" and "stats" that the loader requires. Sizes do not matter
 * because this program never accesses `flows`. Keeping the key and value
 * sizes equal to the real ones preserves the BPF map fingerprint, which
 * makes side-by-side comparison with bpf/xdp_flow.o cleaner if anyone reads
 * map metadata (bpftool, /proc/...) during the run.
 */
struct flow_key {
	__u8  src_addr[16];
	__u8  dst_addr[16];
	__u8  src_mac[6];
	__u8  dst_mac[6];
	__u16 src_port;
	__u16 dst_port;
	__u16 vlan_id;
	__u8  proto;
	__u8  ip_version;
};

struct flow_value {
	__u64 packets;
	__u64 bytes;
	__u64 first_seen_ns;
	__u64 last_seen_ns;
	__u32 ingress_ifindex;
	__u32 rx_queue;
	__u32 tcp_syn_count;
	__u32 tcp_rst_count;
	__u32 tcp_fin_count;
	__u8  tcp_flags_or;
	__u8  tos;
	__u8  ttl_min;
	__u8  ttl_max;
	__u16 pkt_len_min;
	__u16 pkt_len_max;
	__u32 ip_frag_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct flow_key);
	__type(value, struct flow_value);
} flows SEC(".maps");

/*
 * Same shape as in xdp_flow.c so the loader and userspace stats reader both
 * keep working: 4-entry PERCPU_ARRAY of __u64 counters. Only stats[0] is
 * updated here; userspace will read stats[1..3] as zeros.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

SEC("xdp")
int xdp_flow_prog(struct xdp_md *ctx)
{
	__u32 idx = 0;
	__u64 *c = bpf_map_lookup_elem(&stats, &idx);

	if (c)
		(*c)++;

	return xdp_final_action;
}

char LICENSE[] SEC("license") = "GPL";
