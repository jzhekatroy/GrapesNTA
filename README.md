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
