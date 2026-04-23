// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_flow.c — XDP flow aggregation (recommended field set).
 *
 * Parses Ethernet (802.1Q optional), IPv4 / IPv6, TCP / UDP / ICMP / ICMPv6.
 * HASH map flows + ARRAY stats:
 *   stats[0] = total_packets (every packet seen by XDP)
 *   stats[1] = parse_errors  (truncated L2/L3/L4 headers)
 *   stats[2] = map_full      (flows HASH table full, insert failed)
 *   stats[3] = non_ip_pass   (XDP_PASS for non-IPv4/IPv6 traffic: ARP, LLDP, etc.)
 *
 * Identity check (userspace should verify):
 *   total_packets == sum(flow.packets) + parse_errors + map_full + non_ip_pass
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

/* Max entries for the flow HASH. Production traffic on a 40 Gbit/s mirror
 * can peak at >2 million concurrent flows (ipt_NETFLOW maxflows=2M hit its
 * ceiling on one of the audited servers). We default to 4M here — ~400 MB
 * RAM per map — and allow a compile-time override via -DFLOWS_MAP_SIZE=N.
 */
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
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump_stat(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&stats, &idx);
	if (c)
		__sync_fetch_and_add(c, 1);
}

static __always_inline void ipv4_addrs_to_key(struct flow_key *key, __be32 saddr, __be32 daddr)
{
	__builtin_memset(key->src_addr, 0, 16);
	__builtin_memset(key->dst_addr, 0, 16);
	__builtin_memcpy(key->src_addr, &saddr, sizeof(__be32));
	__builtin_memcpy(key->dst_addr, &daddr, sizeof(__be32));
}

static __always_inline int is_ipv4_fragment(const struct iphdr *ip)
{
	__be16 frag_off = ip->frag_off;

	if ((frag_off & bpf_htons(0x2000)) || (frag_off & bpf_htons(0x1FFF)))
		return 1;
	return 0;
}

static __always_inline void merge_ttl(struct flow_value *v, __u8 ttl)
{
	if (ttl < v->ttl_min)
		v->ttl_min = ttl;
	if (ttl > v->ttl_max)
		v->ttl_max = ttl;
}

static __always_inline void merge_pkt_len(struct flow_value *v, __u16 plen)
{
	if (plen < v->pkt_len_min)
		v->pkt_len_min = plen;
	if (plen > v->pkt_len_max)
		v->pkt_len_max = plen;
}

static __always_inline int parse_l4_tcpudp_icmp(struct flow_key *key, __u8 *tcp_flags,
						  __u32 *syn_cnt, __u32 *rst_cnt, __u32 *fin_cnt,
						  void *l4_start, void *data_end, __u8 proto)
{
	void *l4 = l4_start;

	key->proto = proto;

	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcp = l4;

		if ((void *)(tcp + 1) > data_end) {
			bump_stat(1);
			return -1;
		}
		key->src_port = tcp->source;
		key->dst_port = tcp->dest;
		if (tcp->fin) {
			*tcp_flags |= 0x01;
			__sync_fetch_and_add(fin_cnt, 1);
		}
		if (tcp->syn) {
			*tcp_flags |= 0x02;
			__sync_fetch_and_add(syn_cnt, 1);
		}
		if (tcp->rst) {
			*tcp_flags |= 0x04;
			__sync_fetch_and_add(rst_cnt, 1);
		}
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
	} else {
		key->src_port = 0;
		key->dst_port = 0;
	}
	return 0;
}

/* Walk IPv6 extension headers; set *saw_frag if a Fragment header was present. */
static __always_inline int skip_ipv6_exthdrs(void **nexthdr_ptr, __u8 *proto,
					     void *data_end, int *saw_frag)
{
	void *nh = *nexthdr_ptr;
	__u8 p = *proto;

#pragma unroll
	for (int i = 0; i < 6; i++) {
		if (p == IPPROTO_HOPOPTS || p == IPPROTO_ROUTING || p == IPPROTO_DSTOPTS) {
			struct ipv6_opt_hdr *exth = nh;

			if ((void *)(exth + 1) > data_end)
				return -1;
			__u32 hdrlen = (( __u32)exth->hdrlen + 1) * 8;

			if (nh + hdrlen > data_end)
				return -1;
			p = exth->nexthdr;
			nh += hdrlen;
			continue;
		}
		if (p == IPPROTO_FRAGMENT) {
			struct ipv6_frag_hdr {
				__u8 nexthdr;
				__u8 reserved;
				__be16 frag_off;
				__be32 identification;
			} *fh = nh;

			if ((void *)(fh + 1) > data_end)
				return -1;
			*saw_frag = 1;
			p = fh->nexthdr;
			nh += sizeof(*fh);
			continue;
		}
		break;
	}
	*nexthdr_ptr = nh;
	*proto = p;
	return 0;
}

static __always_inline void flow_update_common(struct flow_value *val, __u64 now, __u32 pkt_len,
					       __u8 tcp_flags, __u32 syn_cnt, __u32 rst_cnt,
					       __u32 fin_cnt, __u8 ttl, __u16 wire_len, int frag_inc)
{
	__sync_fetch_and_add(&val->packets, 1);
	__sync_fetch_and_add(&val->bytes, pkt_len);
	val->last_seen_ns = now;
	val->tcp_flags_or |= tcp_flags;
	__sync_fetch_and_add(&val->tcp_syn_count, syn_cnt);
	__sync_fetch_and_add(&val->tcp_rst_count, rst_cnt);
	__sync_fetch_and_add(&val->tcp_fin_count, fin_cnt);
	merge_ttl(val, ttl);
	merge_pkt_len(val, wire_len);
	if (frag_inc)
		__sync_fetch_and_add(&val->ip_frag_count, 1);
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

		ipv4_addrs_to_key(&key, ip->saddr, ip->daddr);
		key.vlan_id = vlan_id;
		key.ip_version = 4;

		__u8 tcp_flags = 0;
		__u32 syn_cnt = 0, rst_cnt = 0, fin_cnt = 0;

		if (parse_l4_tcpudp_icmp(&key, &tcp_flags, &syn_cnt, &rst_cnt, &fin_cnt,
					 l4, data_end, ip->protocol) < 0)
			return XDP_PASS;

		__u64 now = bpf_ktime_get_ns();
		__u16 wire_len = (__u16)(pkt_len > 0xFFFF ? 0xFFFF : pkt_len);
		__u8 ttl = ip->ttl;
		int frag_inc = is_ipv4_fragment(ip);
		struct flow_value *val = bpf_map_lookup_elem(&flows, &key);

		if (val) {
			flow_update_common(val, now, pkt_len, tcp_flags, syn_cnt, rst_cnt,
					   fin_cnt, ttl, wire_len, frag_inc);
		} else {
			struct flow_value nv = {};

			nv.packets = 1;
			nv.bytes = pkt_len;
			nv.first_seen_ns = now;
			nv.last_seen_ns = now;
			nv.ingress_ifindex = ctx->ingress_ifindex;
			nv.rx_queue = ctx->rx_queue_index;
			nv.tcp_syn_count = syn_cnt;
			nv.tcp_rst_count = rst_cnt;
			nv.tcp_fin_count = fin_cnt;
			nv.tcp_flags_or = tcp_flags;
			nv.tos = ip->tos;
			nv.ttl_min = ttl;
			nv.ttl_max = ttl;
			nv.pkt_len_min = wire_len;
			nv.pkt_len_max = wire_len;
			nv.ip_frag_count = frag_inc ? 1 : 0;

			long err = bpf_map_update_elem(&flows, &key, &nv, BPF_NOEXIST);

			if (err == -17) {
				val = bpf_map_lookup_elem(&flows, &key);
				if (val)
					flow_update_common(val, now, pkt_len, tcp_flags, syn_cnt,
							   rst_cnt, fin_cnt, ttl, wire_len, frag_inc);
			} else if (err < 0) {
				bump_stat(2);
			}
		}
		return XDP_PASS;
	}

	if (h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = nh;

		if ((void *)(ip6 + 1) > data_end) {
			bump_stat(1);
			return XDP_PASS;
		}

		struct flow_key key = {};

		__builtin_memset(&key, 0, sizeof(key));
		__builtin_memcpy(key.src_addr, &ip6->saddr, 16);
		__builtin_memcpy(key.dst_addr, &ip6->daddr, 16);
		key.vlan_id = vlan_id;
		key.ip_version = 6;

		__u8 nxt = ip6->nexthdr;
		void *l4 = (void *)(ip6 + 1);
		int saw_frag = 0;

		if (skip_ipv6_exthdrs(&l4, &nxt, data_end, &saw_frag) < 0) {
			bump_stat(1);
			return XDP_PASS;
		}
		if (l4 > data_end) {
			bump_stat(1);
			return XDP_PASS;
		}

		__u8 tcp_flags = 0;
		__u32 syn_cnt = 0, rst_cnt = 0, fin_cnt = 0;

		if (nxt == IPPROTO_ICMPV6) {
			struct icmp6hdr *ic = l4;

			if ((void *)(ic + 1) > data_end) {
				bump_stat(1);
				return XDP_PASS;
			}
			key.proto = IPPROTO_ICMPV6;
			key.src_port = bpf_htons((__u16)ic->icmp6_type << 8 | ic->icmp6_code);
			key.dst_port = 0;
		} else if (parse_l4_tcpudp_icmp(&key, &tcp_flags, &syn_cnt, &rst_cnt, &fin_cnt,
						l4, data_end, nxt) < 0) {
			return XDP_PASS;
		}

		__u64 now = bpf_ktime_get_ns();
		__u16 wire_len = (__u16)(pkt_len > 0xFFFF ? 0xFFFF : pkt_len);
		__u8 ttl = ip6->hop_limit;
		int frag_inc = saw_frag;
		struct flow_value *val = bpf_map_lookup_elem(&flows, &key);

		if (val) {
			flow_update_common(val, now, pkt_len, tcp_flags, syn_cnt, rst_cnt, fin_cnt,
					   ttl, wire_len, frag_inc);
		} else {
			struct flow_value nv = {};

			nv.packets = 1;
			nv.bytes = pkt_len;
			nv.first_seen_ns = now;
			nv.last_seen_ns = now;
			nv.ingress_ifindex = ctx->ingress_ifindex;
			nv.rx_queue = ctx->rx_queue_index;
			nv.tcp_syn_count = syn_cnt;
			nv.tcp_rst_count = rst_cnt;
			nv.tcp_fin_count = fin_cnt;
			nv.tcp_flags_or = tcp_flags;
			nv.tos = 0;
			nv.ttl_min = ttl;
			nv.ttl_max = ttl;
			nv.pkt_len_min = wire_len;
			nv.pkt_len_max = wire_len;
			nv.ip_frag_count = frag_inc ? 1 : 0;

			long err = bpf_map_update_elem(&flows, &key, &nv, BPF_NOEXIST);

			if (err == -17) {
				val = bpf_map_lookup_elem(&flows, &key);
				if (val)
					flow_update_common(val, now, pkt_len, tcp_flags, syn_cnt,
							   rst_cnt, fin_cnt, ttl, wire_len, frag_inc);
			} else if (err < 0) {
				bump_stat(2);
			}
		}
		return XDP_PASS;
	}

	/* Not IPv4 and not IPv6 (ARP, LLDP, STP, 802.1AD with non-IP inner, etc.). */
	bump_stat(3);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
