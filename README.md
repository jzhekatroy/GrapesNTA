# GrapesNTA

XDP/eBPF flow collectors, ClickHouse analytics, Docker workers, and the NTAdmin UI.

**Новый стенд с нуля:** [docs/INSTALL.txt](docs/INSTALL.txt) (текст для инженера) или [docs/INSTALL.md](docs/INSTALL.md).

Repository: [github.com/jzhekatroy/GrapesNTA](https://github.com/jzhekatroy/GrapesNTA)

The rest of this README is the `xdpflowd` collector: build flags, NetFlow export, and the old `ipt_NETFLOW` cutover. Collector binaries still live here; rollups and the UI do not.

**Build (Linux only):** requires `clang`, `libbpf-dev`, `linux-libc-dev` (or kernel headers), Go 1.23+.

```bash
git clone https://github.com/jzhekatroy/GrapesNTA.git
cd GrapesNTA
go mod tidy   # first time: populate go.sum
make clean && make
# binary: ./bin/xdpflowd
# BPF object: ./bpf/xdp_flow.o
```

**RIR country → ClickHouse:** optional Python script [scripts/load_rir_geo.py](scripts/load_rir_geo.py) loads delegated statistics into `geo_prefix_country` and `geo_country_dict` via `clickhouse-client`. See [docs/geoip_country.md](docs/geoip_country.md).

**Traffic rollups → ClickHouse:** aggregate tables `traffic_*` are filled asynchronously by [scripts/traffic_rollup_async.py](scripts/traffic_rollup_async.py) (not sync MV on ingest). Schema: [deploy/schema/60_traffic](deploy/schema/60_traffic). Detach leftover MVs: [deploy/clickhouse/detach_traffic_mvs.sql](deploy/clickhouse/detach_traffic_mvs.sql). On production, grapes-worker runs the rollups. Runbook: [docs/CLICKHOUSE_DB_SETUP_RUNBOOK.md](docs/CLICKHOUSE_DB_SETUP_RUNBOOK.md) §7.

**BMP collector:** standalone pure-Go service [`cmd/bmpgrapes`](cmd/bmpgrapes) accepts BMP TCP sessions from routers and writes `default.bmp_peers` / `default.bmp_route_events` / `default.bgp_updates_1m`. Build with `make build-bmp`, see [docs/BMPGRAPES_MVP.md](docs/BMPGRAPES_MVP.md) and [deploy/schema/30_bmp](deploy/schema/30_bmp).

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

### Production: new stand vs old ipt_NETFLOW cutover

A new stand: [docs/INSTALL.txt](docs/INSTALL.txt).

The ipt_NETFLOW A/B scripts, experimental AF_XDP daemon, and host systemd
timers for rollups/geo are in [`attic/`](attic/). Do not enable them next to
`grapes-worker` / `grapes-enrichment`.

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
