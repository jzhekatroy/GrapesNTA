# GrapesNTA (xdpflowd)

XDP/eBPF flow collector for ISP-style mirror/TAP ports: parses L2/L3/L4 on the NIC, aggregates into a per-flow hash map; userspace reads maps and can emit NDJSON for accuracy tests.

Repository: [github.com/jzhekatroy/GrapesNTA](https://github.com/jzhekatroy/GrapesNTA)

**Build (Linux only):** requires `clang`, `libbpf-dev`, `linux-libc-dev` (or kernel headers), Go 1.23+.

```bash
git clone https://github.com/jzhekatroy/GrapesNTA.git
cd GrapesNTA
go mod tidy   # first time: populate go.sum
make clean && make
# binary: ./bin/xdpflowd
# BPF object: ./bpf/xdp_flow.o
```

Run (root):

```bash
sudo ./bin/xdpflowd -iface ens18 -mode native -bpf ./bpf/xdp_flow.o
```

### Flags

| Flag | Meaning |
|------|---------|
| `-bpf` | Path to compiled `xdp_flow.o` (default `./bpf/xdp_flow.o`) |
| `-iface` | Interface to attach XDP |
| `-mode` | `native` or `generic` |
| `-interval` | Text stats / top-N print interval |
| `-json-out PATH` | Append one NDJSON line per `-json-interval` with `stats` + `aggregate` (+ optional flows) |
| `-json-interval` | JSON dump period (default: same as `-interval`) |
| `-json-include-flows` | Include full `flows` array (large) |
| `-once` | Sleep one `-interval`, optional single JSON line, print top, exit |
| `-top` | Number of lines in top flows |
| `-nf-dst` | NetFlow v9 destinations, comma-separated `host:port` (e.g. `127.0.0.1:2055,127.0.0.1:9999`). Empty = disabled. |
| `-nf-active` | Active timeout — export flows older than this (default `120s`) |
| `-nf-idle` | Idle timeout — export flows with no packets for this long (default `15s`) |
| `-nf-template-interval` | Re-send NFv9 template (default `60s`) |
| `-nf-scan` | How often to walk the map for export (default `1s`) |
| `-nf-source-id` | NFv9 `source_id` (observation domain, default `1`) |
| `-xdp-action` | XDP return for accounted IP packets: `pass` (default, safe) or `drop`. **Use `drop` only on SPAN/mirror interfaces** — drops the packet from the kernel stack after accounting, saving ~30% softirq CPU on a 2.5-3 Mpps flow. Non-IP (ARP, LLDP) always passes. |

### XDP_DROP on SPAN/mirror

For monitoring-only ports where kernel doesn't need to process packets further,
add `-xdp-action drop` to eliminate the `skb_alloc` + `netfilter` + `routing`
cost per packet. This is where the real Phase 3 CPU win lives (as opposed to
`XDP_PASS`, which adds BPF cost on top of the existing kernel path).

```bash
sudo ./bin/xdpflowd -iface enp5s0d1 -mode native -xdp-action drop \
     -nf-dst 127.0.0.1:9996 -nf-active 60s -nf-idle 15s
```

**DO NOT use `-xdp-action drop` on a regular routing interface** — packets will
be silently dropped and forwarding will break.

### NetFlow v9 export

Send flows to `nfcapd` / `goflow2` / any NFv9 collector:

```bash
sudo ./bin/xdpflowd -iface ens18 -mode native -bpf ./bpf/xdp_flow.o \
     -nf-dst 127.0.0.1:2055,127.0.0.1:9996 \
     -nf-active 120s -nf-idle 15s -nf-template-interval 60s
```

Emitted fields (templates 256 = IPv4, 257 = IPv6, both in one Template FlowSet):

`IN_BYTES` (8), `IN_PKTS` (8), `PROTOCOL`, `SRC_TOS`, `TCP_FLAGS`, `L4_SRC_PORT`, `IPV4_SRC_ADDR` / `IPV6_SRC_ADDR`, `INPUT_SNMP` (= `ingress_ifindex`), `L4_DST_PORT`, `IPV4_DST_ADDR` / `IPV6_DST_ADDR`, `FIRST_SWITCHED`, `LAST_SWITCHED`, `MIN_TTL`, `MAX_TTL`, `MIN_PKT_LNGTH`, `MAX_PKT_LNGTH`, `SRC_VLAN`, `IP_PROTOCOL_VERSION`.

Test end-to-end with [`scripts/netflow_test.sh`](scripts/netflow_test.sh): runs xdpflowd → `nfcapd` → compares xdpflowd JSON totals vs `nfdump` aggregate.

```bash
sudo ./scripts/netflow_test.sh ens18 192.168.64.1
```

### Accuracy / baseline (strict thresholds)

Script: [`scripts/accuracy_test.sh`](scripts/accuracy_test.sh)

- Temporarily turns **GRO** off on the test interface (restores defaults afterward).
- Compares **delta** `ethtool -S` `rx_packets` / `rx_bytes` vs:
  - eBPF `stats[0]` total_packets (XDP saw every L2 frame)
  - sum of `flows` map `packets` / `bytes` (IP flows only — ARP etc. will not appear in flows).

**Strict pass (packets):** XDP `stats.total_packets` delta vs ethtool `rx_packets` delta ≥ **99.99%**.

**Bytes:** sum of flow bytes vs ethtool `rx_bytes` may diverge slightly due to non-IP frames; script warns below **99.95%**.

```bash
# On the test VM (iperf3 server elsewhere):
export IPERF3_HOST=203.0.113.10
sudo -E ./scripts/accuracy_test.sh
```

Optional tcpreplay phase:

```bash
export PCAP_IN=/tmp/sample.pcap
sudo -E ./scripts/accuracy_test.sh
```

### PCAP local capture + replay

[`scripts/pcap_replay_test.sh`](scripts/pcap_replay_test.sh) — captures a few seconds on `IFACE`, replays with `tcpreplay`, prints deltas.

```bash
sudo IFACE=ens18 ./scripts/pcap_replay_test.sh
```

### Production deployment: 2-phase migration from ipt_NETFLOW

Scripts [`scripts/prod_observe.sh`](scripts/prod_observe.sh) (zero-risk parallel) and
[`scripts/prod_ab_swap.sh`](scripts/prod_ab_swap.sh) (10-min A/B with auto-restore)
are designed to safely validate and benchmark `xdpflowd` against a running
`ipt_NETFLOW` on an ISP mirror port. Both are reversible: an SSH drop, Ctrl+C,
or a crash restores the original `iptables` rule via `EXIT`/`INT`/`TERM`/`HUP` traps.

**Phase 0 — baseline snapshot (reference state, do this first):**

```bash
sudo ./scripts/prod_snapshot.sh enp5s0d1
# writes /root/xdpflowd_baseline_<TS>/ and symlinks /root/xdpflowd_baseline_latest
# saved: iptables -c (all tables), ip6tables, sysctl net.*, /proc/net/stat/ipt_netflow,
# ethtool -i/-g/-l/-c/-k/-S, ip link/addr/route, ss -ulnp, docker ps + inspect,
# systemd units for goflow2/nfcapd/xdpflowd, NIC counter baselines, manifest.txt
```

At any time later run [`scripts/prod_verify.sh`](scripts/prod_verify.sh) to confirm
the running state matches the snapshot — it diffs iptables rules, checks the
`ipt_NETFLOW` rule is back in place, validates `net.netflow.*` sysctls,
confirms `goflow2` container is running, and asserts XDP is detached.

```bash
sudo ./scripts/prod_verify.sh           # against /root/xdpflowd_baseline_latest
sudo ./scripts/prod_verify.sh /root/xdpflowd_baseline_<TS>
# exit 0 == identical; exit 1 == drift (diffs are printed)
```

Full hard rollback from a snapshot:

```bash
sudo iptables-restore  < /root/xdpflowd_baseline_latest/10_iptables_save_counters.txt
sudo ip6tables-restore < /root/xdpflowd_baseline_latest/10_ip6tables_save_counters.txt
```

**Phase 1 — parallel observation (no pipeline changes):**

```bash
sudo ./scripts/prod_observe.sh 300 enp5s0d1 12055
```

Runs `xdpflowd` in `XDP_PASS` on the mirror iface, exports NFv9 to a **separate**
port (12055) to its own `nfcapd`. `ipt_NETFLOW` / `goflow2` / ClickHouse keep
running untouched. Prints NIC deltas, ipt_NETFLOW /proc counters, xdpflowd stats,
and `nfdump` aggregates — compare them to confirm `xdpflowd` counts match.

**Phase 2 — temporary swap (writes to real destinations, 10 min):**

```bash
sudo ./scripts/prod_ab_swap.sh --dry-run                              # rehearse
sudo ./scripts/prod_ab_swap.sh 600 enp5s0d1 127.0.0.1:9996,127.0.0.1:9999
```

Automatically refreshes the baseline snapshot if `/root/xdpflowd_baseline_latest`
is older than 1 hour (otherwise reuses it), detects the exact `-j NETFLOW` rule
in `raw`/`mangle`/`nat`, takes an additional `iptables-save -c` backup under
`/root/iptables-save-before-<TS>.txt`, installs traps, removes the rule, starts
`xdpflowd` on the same destinations (`127.0.0.1:9996`, `127.0.0.1:9999`), runs
a watchdog that aborts on stall, always restores the rule on exit, **and then
runs `prod_verify.sh` to confirm the live state matches the baseline**.
Measure CPU (`mpstat`, `pidstat`), NIC drops (`ethtool -S`) and verify ClickHouse
still receives rows during the window.

**Panic recovery** (if the trap somehow did not run):

```bash
sudo ./scripts/prod_restore.sh                              # show options
sudo ./scripts/prod_restore.sh /tmp/xdpflowd_abswap_<TS>/state.env
sudo ./scripts/prod_restore.sh --full-restore /root/iptables-save-before-<TS>.txt
```

### Flow fields (kernel / raw)

Per flow (see `bpf/xdp_flow.c`):

- IPv4/IPv6 addresses (v4 stored in first 4 bytes of 16-byte key fields)
- Ports (network order in map; ICMP/ICMPv6 type+code in `src_port`)
- VLAN id (802.1Q / 802.1AD), protocol, IP version
- Packets, bytes, first/last seen (ktime ns)
- `ingress_ifindex`, `rx_queue`
- TCP SYN/RST/FIN counts, TCP flags OR, IPv4 ToS
- TTL min/max (IPv4 TTL / IPv6 hop limit)
- L2 frame length min/max (`pkt_len_min` / `pkt_len_max`)
- `ip_frag_count` (IPv4 MF/offset; IPv6 if Fragment header seen)

No GeoIP/ASN enrichment (by design).
