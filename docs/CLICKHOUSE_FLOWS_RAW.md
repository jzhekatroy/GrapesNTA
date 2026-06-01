# ClickHouse flow ingest: `default.flows_raw` and direct `xdpflowd` insert

## Production table (`default.flows_raw`)

This is the actual production DDL observed on `sel` via `SHOW CREATE TABLE default.flows_raw`
(before enrichment/source columns; `deploy/clickhouse/flows_raw_extensions.sql` adds the
classifier columns and `source_id`):

```sql
CREATE TABLE default.flows_raw
(
    `date` Date,
    `time_inserted_ns` DateTime64(9),
    `time_received_ns` DateTime64(9),
    `time_flow_start_ns` DateTime64(9),
    `sequence_num` UInt32,
    `sampling_rate` UInt64,
    `sampler_address` FixedString(16),
    `src_addr` FixedString(16),
    `dst_addr` FixedString(16),
    `src_as` UInt32,
    `dst_as` UInt32,
    `etype` UInt32,
    `proto` UInt32,
    `src_port` UInt32,
    `dst_port` UInt32,
    `bytes` UInt64,
    `packets` UInt64
)
ENGINE = MergeTree
PARTITION BY date
ORDER BY time_received_ns
TTL date + toIntervalDay(5)
SETTINGS index_granularity = 8192;
```

Phase scripts (`prod_phase3_drop.sh`) currently compare:

| Usage | Column | Notes |
|-------|--------|-------|
| Time window | `time_received_ns` | `DateTime64(9)` |
| Aggregates | `packets` | `UInt64` |
| Aggregates | `bytes` | `UInt64` |

The live table is fed by the existing NetFlow → collector pipeline:

```text
ipt_NETFLOW / xdpflowd
  -> NetFlow v9 UDP
  -> local collector
  -> ClickHouse default.flows_raw
```

Постоянный режим `xdpflowd` на `sel` под **systemd** (direct INSERT + spool, rollback на `ipt_NETFLOW`): см. [`SEL_PERMANENT_XDPFLOWD_RUNBOOK.md`](SEL_PERMANENT_XDPFLOWD_RUNBOOK.md).

## Recommended staging table for direct inserts

For the first direct-ingest test, create a staging table with the **same shape** as `default.flows_raw`.
This keeps A/B validation honest and makes a later production switch a table-name/config change rather than a schema rewrite.

```sql
CREATE TABLE IF NOT EXISTS default.flows_raw_xdp_direct
(
    `date` Date,
    `time_inserted_ns` DateTime64(9),
    `time_received_ns` DateTime64(9),
    `time_flow_start_ns` DateTime64(9),
    `sequence_num` UInt32,
    `sampling_rate` UInt64,
    `sampler_address` FixedString(16),
    `src_addr` FixedString(16),
    `dst_addr` FixedString(16),
    `src_as` UInt32,
    `dst_as` UInt32,
    `etype` UInt32,
    `proto` UInt32,
    `src_port` UInt32,
    `dst_port` UInt32,
    `bytes` UInt64,
    `packets` UInt64,
    `source_id` LowCardinality(String) DEFAULT 'xdp-default'
)
ENGINE = MergeTree
PARTITION BY date
ORDER BY time_received_ns
TTL date + toIntervalDay(5)
SETTINGS index_granularity = 8192;
```

`source_id` identifies the observation point (see `deploy/clickhouse/net_flow_sources.sql`).
`xdpflowd` always writes it (default `xdp-default`), so any direct-insert target
table must include this column.

## Field mapping (BPF → `flows_raw` shape)

| Column | Source / value |
|----------------|--------|
| `date` | `toDate(time_received_ns)` |
| `time_inserted_ns` | Wall time at ClickHouse insert (`now64(9)` equivalent from `xdpflowd`) |
| `time_received_ns` | Wall time when `xdpflowd` exports the row |
| `time_flow_start_ns` | `ExporterStart + (FirstSeenNs - BpfStartNs)` |
| `sequence_num` | `0` for direct staging until a downstream consumer requires exporter sequence semantics |
| `sampling_rate` | `1` (no sampling in current XDP path) |
| `sampler_address` | 16-byte exporter/source address; set via `-ch-sampler-addr` / `XDP_CH_SAMPLER_ADDR` or zero until configured |
| `src_addr` / `dst_addr` | 16 raw bytes from `FlowKey`; IPv4 stored in the first 4 bytes with the rest zeroed to match current BPF key layout |
| `src_as` / `dst_as` | Legacy ASN columns. With classifier enabled they mirror `src_asn` / `dst_asn`; otherwise `0`. |
| `src_asn` / `dst_asn` | Origin ASN from BGP trie loaded from `bgp_prefix_origin_current`. Requires `deploy/clickhouse/flows_raw_extensions.sql`. |
| `direction` | `in`, `out`, `internal`, `transit`, `unknown`; computed in `xdpflowd` from endpoint scope (`local/customer/remote`), not directly from VLAN. |
| `src_attachment_*` / `dst_attachment_*` | VLAN/link context: kind, boundary, label, operator. This answers "where was the packet seen?". |
| `src_endpoint_scope` / `dst_endpoint_scope` | IP ownership relative to us: `local`, `customer`, `remote`, `unknown`. This answers "whose IP is it?". |
| `src_endpoint_source` / `dst_endpoint_source` | Decision source for endpoint scope: `asn`, `prefix`, `fallback`, `unknown`. |
| `src_network_name` / `dst_network_name` | Prefix name when IP matched `local_networks_enabled`. |
| `src_network_role` / `dst_network_role` | Prefix role when IP matched `local_networks_enabled` (`customer`, `local`, `internal`, `mgmt`, ...). |
| `src_kind` / `dst_kind` | Compatibility columns; new rows mirror `src_endpoint_scope` / `dst_endpoint_scope`. |
| `src_label` / `dst_label` | Compatibility endpoint label (ASN name or prefix name). VLAN label is in `src_attachment_label` / `dst_attachment_label`. |
| `src_operator` / `dst_operator` | Compatibility endpoint operator id. VLAN operator is in `src_attachment_operator` / `dst_attachment_operator`. |
| `src_vlan` / `dst_vlan` | Current XDP path writes the outer VLAN to `src_vlan`; `dst_vlan` is `0` until an exporter supplies a separate destination VLAN. |
| `etype` | `0x0800` for IPv4, `0x86DD` for IPv6 |
| `proto` | `FlowKey.Proto` |
| `src_port` / `dst_port` | Host-endian ports from BPF key (`keyPortHost`) |
| `bytes` / `packets` | `FlowValue.Bytes` / `FlowValue.Packets` |
| `source_id` | Logical observation point from `-source-id` / `XDPFLOWD_SOURCE_ID` (default `xdp-default`). |

## A/B vs legacy NetFlow→ClickHouse path

1. Create the staging table on ClickHouse using the production-shaped DDL above.
2. Run `xdpflowd` with **both** the existing NetFlow destinations (`-nf-dst …`) **and** direct insert:
   ```bash
   ./bin/xdpflowd ... \
     -nf-dst '127.0.0.1:9996,127.0.0.1:9999' \
     -ch-dsn 'clickhouse://USER:PASS@HOST:9000/default' \
     -ch-table default.flows_raw_xdp_direct
   ```
   Or via `prod_ab_swap.sh` / `prod_phase3_drop.sh`:
   ```bash
   export XDP_CH_DSN='clickhouse://USER:PASS@HOST:9000/default'
   export XDP_CH_TABLE='default.flows_raw_xdp_direct'
   ```

   Use the **native** TCP port (often `9000`), not the HTTP client port.

3. Compare **legacy DB path** (`default.flows_raw` from collector) vs **staging** (`default.flows_raw_xdp_direct`) using `sum(packets)` / `sum(bytes)` over the same wall-clock windows (`time_received_ns`).
4. Exact equality is not expected (flow timeouts differ slightly, bounded CH queue may drop under overload); large systematic gaps need investigation.
5. After validation, either point direct insert at `default.flows_raw` or keep a direct table and wire downstream reads/materialized views to it. Keep the NetFlow port used for local capture unchanged.

## Durable spool + parallel ClickHouse writers

For high-throughput hosts, enable append-only disk spool + parallel `INSERT` workers
so the BPF scan loop is not blocked on database latency. Spool stores **internal**
gob-encoded `FlowRow` batches (not `nfdump`); replay recovers after ClickHouse outages.

| Flag | Purpose |
|------|---------|
| `-ch-spool-mode` | `off` (default) — direct bounded queue; `on` — spool best-effort; `required` — `os.Exit(1)` if append fails. |
| `-ch-spool-dir` | Root directory (`segments/`, `meta/consumer.json`). Use a dedicated fast disk, **not** the terabyte `nfdump` volume. |
| `-ch-spool-segment-size` | Rotate `.seg` files after this many bytes (default 256MiB). |
| `-ch-spool-max-bytes` | Reject appends when total segment bytes exceed limit (`0` = unlimited). |
| `-ch-spool-frame-max-records` | Split large scan batches into bounded frames / INSERTs (default 50k rows). |
| `-ch-spool-fsync-interval` | Best-effort `fsync` cadence (`0` = fsync every append). |
| `-ch-spool-shutdown-drain` | Bounded wait for spool backlog to reach ClickHouse on shutdown (`0` = leave backlog for replay). |
| `-ch-writers` | Parallel inserters draining spool (default 4). |
| `-ch-sampler-addr` | IPv4/IPv6 for `sampler_address` (16-byte FixedString; IPv4 in first 4 octets). |

`prod_ab_swap.sh` wires env:`XDP_CH_SPOOL_*`, `XDP_CH_WRITERS`, `XDP_CH_SAMPLER_ADDR`.

**Contract**: spool is a **delivery queue**, not the user archive; local truth stays `nfcapd`/`nfdump`. See [`FLOW_STORAGE_CONTRACTS.md`](FLOW_STORAGE_CONTRACTS.md).

## Heavy export / large flow maps

`-heavy-export` shortens `-nf-active` (60s), `-nf-idle` (10s), and `-nf-scan` (500ms)
so flows leave the BPF map more often and shutdown final flush stays bounded.
`prod_ab_swap.sh` / `prod_phase3_drop.sh` support `XDP_HEAVY_SERVER=1` with the same idea
(longer default `XDP_SHUTDOWN_GRACE` on heavy hosts).

For long-running production mode, prefer low-observability overhead:

- `-top 0` disables the expensive full-map top-flow sort; the wrapper default is `XDP_TOP=0`.
- omit `-json-out`, or set `XDP_JSON_OUT_ENABLE=0` in wrappers, to avoid periodic full-map JSON snapshots.
- use `bpf/xdp_flow_fast.o` (`make bpf-fast`) when enriched packet-level fields are not needed; it preserves the userspace ABI and NetFlow/ClickHouse shape while doing less per-packet work.

### Best observed `netflow` profile

On the heavily loaded `netflow` host with `mlx4_en`, the best observed production-replacement profile was:

- `XDP_MODE=generic`
- `XDP_ACTION=drop`
- `XDP_BPF_OBJ=./bpf/xdp_flow.o`
- `NF_DSTS=127.0.0.1:9996`
- `XDP_STOP_GOFLOW2=1`
- `XDP_GOFLOW2_CONTAINERS=kcg-goflow2-1`
- `XDP_CH_SPOOL_MODE=required`
- `XDP_CH_SPOOL_DIR=/var/lib/xdpflowd/ch-spool`
- `XDP_CH_SPOOL_FRAME_MAX_RECORDS=50000`
- `XDP_CH_WRITERS=8`
- IRQ spread enabled when prompted by `prod_phase3_drop.sh`

For an honest replacement test, stop only the production `goflow2` container (`kcg-goflow2-1`) during the XDP window. Otherwise the old `goflow2 -> DB` path keeps consuming CPU and can write overlapping ClickHouse data while `xdpflowd` is being evaluated. Leave replay/test containers such as `replay-goflow2-1` alone unless explicitly testing them.

Observed result for the best run: ClickHouse spool drained fully (`records_spooled == records_acked`, no insert errors), CPU softirq dropped materially, and `rx_fifo_errors` stayed close to the already-present baseline. Later runs showed much higher baseline and XDP `rx_fifo_errors` after repeated XDP attach/detach and `mlx4_en` link/IRQ events (`Link Down/Up`, `No irq handler for vector`), so those later loss numbers should be treated as NIC/driver state dependent rather than a ClickHouse spool regression.

### Best current kernel 6.x profile

For the less loaded kernel 6.x host (`sel`), use the same conservative production-replacement profile for validation and long-run tests:

- `XDP_MODE=generic`
- `XDP_ACTION=drop`
- `XDP_BPF_OBJ=./bpf/xdp_flow.o`
- `NF_DSTS=127.0.0.1:9996`
- `XDP_STOP_GOFLOW2=1`
- `XDP_GOFLOW2_CONTAINERS=kcg-goflow2-1`
- `XDP_CH_TABLE=default.flows_raw`
- `XDP_CH_SPOOL_MODE=required`
- `XDP_CH_SPOOL_DIR=/var/lib/xdpflowd/ch-spool`
- `XDP_CH_SPOOL_MAX_BYTES=214748364800`
- `XDP_CH_SPOOL_FRAME_MAX_RECORDS=50000`
- `XDP_HEAVY_EXPORT=0`
- `XDP_NF_ACTIVE=60s`
- `XDP_NF_IDLE=10s`
- `XDP_NF_SCAN=1s`
- `XDP_CH_SPOOL_SHUTDOWN_DRAIN=300s` for permanent mode
- `XDP_CH_SAMPLER_ADDR=127.0.0.1`
- `XDP_CH_WRITERS=8`
- `WATCHDOG_STALL_SEC=300`
- `XDP_TOP=0`
- `XDP_JSON_OUT_ENABLE=0`
- no manual IRQ spread for the current `sel` baseline

This profile intentionally uses the full `xdp_flow.o` BPF object instead of the fast variant. The initial `500ms` scan was safe but used more CPU; the confirmed permanent `sel` profile uses `1s` scan with stable `rx_fifo_errors=0/sec`, lower softirq than legacy, local `nfcapd` output, and direct ClickHouse spool.

#### Kernel 6.12 baseline note (`sel`)

After upgrading `sel` to Debian backports kernel `6.12.74+deb12-amd64`, the host showed baseline RX drops before any XDP test:

- driver: `mlx4_en`
- firmware: `2.42.5000`
- interface: `enp5s0d1`
- XDP attached: no
- `rx_pps`: ~164k
- `rx_gbps`: ~1
- `rx_fifo_errors`: ~31k/sec
- `rx_dropped`: ~31k/sec
- `rx_errors`: 0
- CPU baseline: mostly idle (`~92%` all-CPU idle, `~4%` softirq)
- dmesg after boot: no XDP errors and no repeated `mlx4_en` link flaps in the sampled window

This means the kernel 6.12 host already drops packets in the NIC/RX path before `xdpflowd` is started. Do not treat a replacement test on this state as an `xdpflowd` result until baseline is understood. First investigate IRQ distribution, RX rings, coalescing, flow-control, and NAPI/sysctl settings with:

```bash
ethtool -g enp5s0d1
ethtool -c enp5s0d1
ethtool -a enp5s0d1
ethtool -l enp5s0d1
sysctl net.core.netdev_budget net.core.netdev_budget_usecs net.core.netdev_max_backlog
ethtool -S enp5s0d1 | egrep 'rx[0-9]+_(packets|bytes|dropped|xdp_drop)|rx_fifo_errors|rx_dropped|rx_pause|rx_pause_duration|rx_pause_transition'
```

Then test IRQ spread alone, without XDP, and only proceed to the 5-minute XDP replacement test if baseline `rx_fifo_errors` is acceptable or clearly understood.

## Rollback / safety

Direct ClickHouse insert is disabled by default. The original path remains:

```text
xdpflowd -nf-dst 127.0.0.1:9996,127.0.0.1:9999
```

Operational rollback:

1. Remove or comment `XDP_CH_TABLE` / `XDP_CH_DSN` in `/root/.grapesnta-clickhouse.env`.
2. Restart the test or daemon. `xdpflowd` will continue exporting NetFlow only.
3. If staging data should be removed:

   ```sql
   DROP TABLE IF EXISTS default.flows_raw_xdp_direct;
   ```

This does not touch `default.flows_raw` or the local NetFlow capture port.
