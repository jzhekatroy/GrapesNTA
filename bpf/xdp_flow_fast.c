// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_flow_fast.c — lean flow-accounting profile for performance comparison.
 *
 * Loader/userspace compatibility is intentionally identical to xdp_flow.c:
 *   - program name: xdp_flow_prog
 *   - maps: flows, stats
 *   - const: xdp_final_action
 *
 * Compared to xdp_flow.c this profile keeps the same flow_key/flow_value ABI
 * and NetFlow output shape, but reduces per-packet work:
 *   - only Ethernet + optional single VLAN + IPv4/IPv6 + TCP/UDP/ICMP parsing
 *   - no IPv6 extension-header walk
 *   - no TTL min/max merge on existing flows
 *   - no packet length min/max merge on existing flows
 *   - no per-flow SYN/RST/FIN counters
 *   - no fragment accounting
 *
 * Existing-flow updates are reduced to:
 *   packets += 1
 *   bytes += pkt_len
 *   last_seen_ns = now
 *   tcp_flags_or |= flags
 *
 * This is still heavier than xdp_light.c because it does real map lookup/update
 * and produces NetFlow-compatible flow records. It is meant to answer how much
 * CPU and NIC pressure comes from the "rich" fields in xdp_flow.c.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x0081
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

const volatile __u32 xdp_final_action = XDP_PASS;

struct flow_key {
	__u8  src_addr[16];
	__u8  dst_addr[16];
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

#ifndef FLOWS_MAP_SIZE
#define FLOWS_MAP_SIZE 4000000
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLOWS_MAP_SIZE);
	__type(key, struct flow_key);
	__type(value, struct flow_value);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump_stat(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&stats, &idx);

	if (c)
		(*c)++;
}

static __always_inline void ipv4_addrs_to_key(struct flow_key *key, __be32 saddr, __be32 daddr)
{
	__builtin_memset(key->src_addr, 0, 16);
	__builtin_memset(key->dst_addr, 0, 16);
	__builtin_memcpy(key->src_addr, &saddr, sizeof(__be32));
	__builtin_memcpy(key->dst_addr, &daddr, sizeof(__be32));
}

static __always_inline int parse_l4_ports(struct flow_key *key, void *l4, void *data_end,
					  __u8 proto, __u8 *tcp_flags)
{
	key->proto = proto;
	*tcp_flags = 0;

	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcp = l4;

		if ((void *)(tcp + 1) > data_end) {
			bump_stat(1);
			return -1;
		}
		key->src_port = tcp->source;
		key->dst_port = tcp->dest;
		if (tcp->fin)
			*tcp_flags |= 0x01;
		if (tcp->syn)
			*tcp_flags |= 0x02;
		if (tcp->rst)
			*tcp_flags |= 0x04;
		if (tcp->psh)
			*tcp_flags |= 0x08;
		if (tcp->ack)
			*tcp_flags |= 0x10;
		if (tcp->urg)
			*tcp_flags |= 0x20;
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *udp = l4;

		if ((void *)(udp + 1) > data_end) {
			bump_stat(1);
			return -1;
		}
		key->src_port = udp->source;
		key->dst_port = udp->dest;
	} else if (proto == IPPROTO_ICMP) {
		__u8 *icmp = l4;

		if (icmp + 2 > (__u8 *)data_end) {
			bump_stat(1);
			return -1;
		}
		key->src_port = bpf_htons((__u16)icmp[0] << 8 | icmp[1]);
		key->dst_port = 0;
	} else if (proto == IPPROTO_ICMPV6) {
		struct icmp6hdr *ic = l4;

		if ((void *)(ic + 1) > data_end) {
			bump_stat(1);
			return -1;
		}
		key->src_port = bpf_htons((__u16)ic->icmp6_type << 8 | ic->icmp6_code);
		key->dst_port = 0;
	} else {
		key->src_port = 0;
		key->dst_port = 0;
	}

	return 0;
}

static __always_inline void update_existing_flow(struct flow_value *val, __u64 now,
						 __u32 pkt_len, __u8 tcp_flags)
{
	__sync_fetch_and_add(&val->packets, 1);
	__sync_fetch_and_add(&val->bytes, pkt_len);
	val->last_seen_ns = now;
	val->tcp_flags_or |= tcp_flags;
}

static __always_inline void init_flow(struct flow_value *val, struct xdp_md *ctx,
				      __u64 now, __u32 pkt_len, __u8 tcp_flags,
				      __u8 tos, __u8 ttl)
{
	__builtin_memset(val, 0, sizeof(*val));
	val->packets = 1;
	val->bytes = pkt_len;
	val->first_seen_ns = now;
	val->last_seen_ns = now;
	val->ingress_ifindex = ctx->ingress_ifindex;
	val->rx_queue = ctx->rx_queue_index;
	val->tcp_flags_or = tcp_flags;
	val->tos = tos;
	val->ttl_min = ttl;
	val->ttl_max = ttl;
	val->pkt_len_min = (__u16)(pkt_len > 0xFFFF ? 0xFFFF : pkt_len);
	val->pkt_len_max = (__u16)(pkt_len > 0xFFFF ? 0xFFFF : pkt_len);
}

static __always_inline int account_flow(struct xdp_md *ctx, struct flow_key *key,
					__u32 pkt_len, __u8 tcp_flags,
					__u8 tos, __u8 ttl)
{
	__u64 now = bpf_ktime_get_ns();
	struct flow_value *val = bpf_map_lookup_elem(&flows, key);

	if (val) {
		update_existing_flow(val, now, pkt_len, tcp_flags);
		return 0;
	}

	struct flow_value nv = {};

	init_flow(&nv, ctx, now, pkt_len, tcp_flags, tos, ttl);

	long err = bpf_map_update_elem(&flows, key, &nv, BPF_NOEXIST);

	if (err == -17) {
		val = bpf_map_lookup_elem(&flows, key);
		if (val)
			update_existing_flow(val, now, pkt_len, tcp_flags);
	} else if (err < 0) {
		bump_stat(2);
	}

	return 0;
}

SEC("xdp")
int xdp_flow_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 pkt_len = (__u32)((unsigned long)data_end - (unsigned long)data);

	bump_stat(0);

	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end) {
		bump_stat(1);
		return XDP_PASS;
	}

	__u16 vlan_id = 0;
	__be16 h_proto = eth->h_proto;
	void *nh = (void *)(eth + 1);

	if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr {
			__be16 tci;
			__be16 encap_proto;
		} *vh = nh;

		if ((void *)(vh + 1) > data_end) {
			bump_stat(1);
			return XDP_PASS;
		}
		vlan_id = bpf_ntohs(vh->tci) & 0x0FFF;
		h_proto = vh->encap_proto;
		nh = (void *)(vh + 1);
	}

	if (h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = nh;

		if ((void *)(ip + 1) > data_end) {
			bump_stat(1);
			return XDP_PASS;
		}

		__u32 ihl = ip->ihl * 4;

		if (ihl < sizeof(*ip)) {
			bump_stat(1);
			return XDP_PASS;
		}

		void *l4 = (void *)ip + ihl;

		if (l4 > data_end) {
			bump_stat(1);
			return XDP_PASS;
		}

		struct flow_key key = {};
		__u8 tcp_flags = 0;

		ipv4_addrs_to_key(&key, ip->saddr, ip->daddr);
		key.vlan_id = vlan_id;
		key.ip_version = 4;

		if (parse_l4_ports(&key, l4, data_end, ip->protocol, &tcp_flags) < 0)
			return XDP_PASS;

		account_flow(ctx, &key, pkt_len, tcp_flags, ip->tos, ip->ttl);
		return xdp_final_action;
	}

	if (h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = nh;

		if ((void *)(ip6 + 1) > data_end) {
			bump_stat(1);
			return XDP_PASS;
		}

		void *l4 = (void *)(ip6 + 1);

		if (l4 > data_end) {
			bump_stat(1);
			return XDP_PASS;
		}

		struct flow_key key = {};
		__u8 tcp_flags = 0;

		__builtin_memcpy(key.src_addr, &ip6->saddr, 16);
		__builtin_memcpy(key.dst_addr, &ip6->daddr, 16);
		key.vlan_id = vlan_id;
		key.ip_version = 6;

		if (parse_l4_ports(&key, l4, data_end, ip6->nexthdr, &tcp_flags) < 0)
			return XDP_PASS;

		account_flow(ctx, &key, pkt_len, tcp_flags, 0, ip6->hop_limit);
		return xdp_final_action;
	}

	bump_stat(3);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
