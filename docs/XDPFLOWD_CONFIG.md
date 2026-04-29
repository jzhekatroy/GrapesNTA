# xdpflowd config file

`xdpflowd` can read a flat YAML config:

```bash
./bin/xdpflowd -config /etc/grapesnta/xdpflowd.yaml
```

CLI flags override config values. This keeps production wrappers flexible: keep stable
defaults in YAML and override `iface`, `nf_dst`, test duration, or table names from
`prod_ab_swap.sh`.

`prod_ab_swap.sh` also accepts:

```bash
XDP_CONFIG_FILE=/etc/grapesnta/xdpflowd.yaml ./scripts/prod_ab_swap.sh 600 enp5s0d1
```

## Recommended production shape

For the target architecture:

- keep local archive through `nf_dst: "127.0.0.1:9996"`;
- enable spool with `ch_spool_mode: required`;
- point `ch_table` at `default.flows_raw`;
- put spool on a dedicated fast local disk, not on the large `nfdump` archive volume.

Example without secrets:

```yaml
# XDP attach / daemon
bpf: ./bpf/xdp_flow.o
iface: enp5s0d1
mode: generic
xdp_action: drop
interval: 5s

# NetFlow v9 local archive contract
nf_dst: "127.0.0.1:9996"
nf_active: 60s
nf_idle: 10s
nf_template_interval: 60s
nf_scan: 500ms
nf_source_id: 1
heavy_export: true

# ClickHouse production contract
# Prefer injecting credentials via env / wrapper rather than committing DSNs.
ch_dsn: "clickhouse://USER:PASS@HOST:9000/default"
ch_table: default.flows_raw
ch_sampler_addr: "10.0.0.10"

# Direct sink settings (used only with ch_spool_mode: off)
ch_batch_size: 50000
ch_flush_interval: 5s
ch_queue_size: 4096

# Durable spool -> parallel ClickHouse writers
ch_spool_mode: required
ch_spool_dir: /var/lib/xdpflowd/ch-spool
ch_spool_segment_size: 268435456   # 256 MiB
ch_spool_max_bytes: 107374182400   # 100 GiB
ch_spool_fsync_interval: 1s
ch_spool_shutdown_drain: 60s       # bounded wait for final flush delivery
ch_writers: 4
```

## Parameters

| Key | Meaning |
|-----|---------|
| `bpf`, `iface`, `mode`, `xdp_action` | BPF object and XDP attach behavior. `drop` only on SPAN/mirror interfaces. |
| `nf_dst` | NetFlow v9 destinations. Keep `127.0.0.1:9996` for local `nfcapd/nfdump`. |
| `nf_active`, `nf_idle`, `nf_scan` | Flow export cadence. Heavy servers should use short active/idle and frequent scan. |
| `heavy_export` | Shortcut for `60s/10s/500ms`; explicit CLI flags still override config before runtime preset rules. |
| `ch_dsn`, `ch_table` | ClickHouse native protocol DSN and target table (`default.flows_raw`). |
| `ch_sampler_addr` | Exporter identity stored in `sampler_address`. |
| `ch_spool_mode` | `off`, `on`, or `required`. Use `required` for production replacement. |
| `ch_spool_dir` | Durable segment directory (`segments/`, `meta/consumer.json`). |
| `ch_spool_max_bytes` | Backpressure cap. In `required`, exceeding it fails daemon so wrapper can roll back. |
| `ch_spool_shutdown_drain` | Optional bounded wait for backlog delivery on SIGTERM. Use `60s` for integrity tests; use `0s` when fast rollback is more important. |
| `ch_writers` | Parallel ClickHouse insert workers reading from spool. |

