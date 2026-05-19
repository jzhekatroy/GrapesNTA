# xdpflowd classifier: VLAN + ASN + Prefix

`xdpflowd` can enrich every ClickHouse flow row before insert. The goal is to
avoid heavy dashboard queries over `flows_raw`.

## Data Sources

The classifier refreshes these ClickHouse views/tables into memory:

- `default.bgp_prefix_origin_current`: BGP prefix -> origin ASN.
- `default.vlan_map_enabled`: outer VLAN -> kind/label/operator.
- `default.local_asns_enabled`: ASNs treated as local/customer.
- `default.local_networks_enabled`: prefixes treated as local/customer.

Priority:

```text
VLAN > local ASN > local prefix
```

MVP decisions:

- VLAN id is global, not scoped by sampler/interface.
- Only the outer VLAN tag is used.
- Private ASNs are not local by default. Add them explicitly to `local_asns`.
- `transit` is one category for external -> external.

## Required DDL

Apply before enabling the classifier:

```bash
clickhouse-client ... --multiquery < deploy/clickhouse/local_operators.sql
clickhouse-client ... --multiquery < deploy/clickhouse/local_networks.sql
clickhouse-client ... --multiquery < deploy/clickhouse/local_asns.sql
clickhouse-client ... --multiquery < deploy/clickhouse/vlan_map.sql
clickhouse-client ... --multiquery < deploy/clickhouse/flows_raw_extensions.sql
clickhouse-client ... --multiquery < deploy/clickhouse/traffic_direction_1m.sql
clickhouse-client ... --multiquery < deploy/clickhouse/traffic_chart_1m.sql
clickhouse-client ... --multiquery < deploy/clickhouse/traffic_uplink_1m.sql
clickhouse-client ... --multiquery < deploy/clickhouse/traffic_customer_1m.sql
```

Seed the current customer prefixes:

```bash
LOCALOPERATORS_CH_HOST=95.215.1.30 \
LOCALOPERATORS_CH_PORT=6124 \
LOCALOPERATORS_CH_USER=develop \
LOCALOPERATORS_CH_PASSWORD='...' \
python3 scripts/load_local_operators.py
```

Seed VLANs with direct SQL inserts:

```bash
clickhouse-client ... --multiquery < deploy/clickhouse/vlan_map_seed_example.sql
```

## Runtime Config

In `/etc/xdpflowd/xdpflowd.env`:

```bash
XDP_CLASSIFIER=1
XDP_CLASSIFIER_REFRESH=60s
XDP_CLASSIFIER_BGP_TABLE=default.bgp_prefix_origin_current
XDP_CLASSIFIER_LOCAL_NETWORKS_VIEW=default.local_networks_enabled
XDP_CLASSIFIER_LOCAL_ASNS_VIEW=default.local_asns_enabled
XDP_CLASSIFIER_VLAN_VIEW=default.vlan_map_enabled
```

The classifier uses the same `XDP_CH_DSN` as ClickHouse inserts.

CLI equivalent:

```bash
./bin/xdpflowd \
  ... \
  -ch-dsn 'clickhouse://USER:PASS@HOST:9000/default' \
  -ch-table default.flows_raw \
  -classifier \
  -classifier-refresh 60s
```

## Written Columns

`xdpflowd` writes:

- `src_as` / `dst_as`: kept for legacy compatibility.
- `src_asn` / `dst_asn`: origin ASN from BGP trie.
- `direction`: `in`, `out`, `internal`, `transit`, `unknown`.
- `src_kind` / `dst_kind`: `local`, `customer`, `uplink`, `ix`, `remote`, etc.
- `src_label` / `dst_label`: uplink/customer label when known.
- `src_operator` / `dst_operator`: stable operator id.
- `src_vlan` / `dst_vlan`: current XDP path writes outer VLAN to `src_vlan`;
  `dst_vlan` stays `0` until an exporter supplies separate destination VLAN.

## Direction Rules

```text
no local config                          -> out
src local  && dst local                  -> internal
src local  && dst remote                 -> out
src remote && dst local                  -> in
src remote && dst remote                 -> transit
```

Local kinds:

```text
local, customer, internal, mgmt
```

Remote kinds:

```text
remote, uplink, ix, peering, unknown
```

## Checks

Last classifier refresh:

```bash
journalctl -u xdpflowd -n 100 --no-pager | grep 'traffic classifier'
```

ClickHouse rows with enrichment:

```sql
SELECT
    direction,
    count() AS rows,
    sum(bytes) AS bytes,
    countIf(src_asn != 0 OR dst_asn != 0) AS rows_with_asn,
    countIf(src_vlan != 0 OR dst_vlan != 0) AS rows_with_vlan
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 5 MINUTE
GROUP BY direction
ORDER BY bytes DESC;
```

Aggregate checks:

```sql
SELECT max(minute), direction, sum(bytes)
FROM default.traffic_direction_1m
WHERE minute >= now() - INTERVAL 15 MINUTE
GROUP BY direction
ORDER BY sum(bytes) DESC;
```

If `direction='unknown'` grows after enabling classifier, check:

- `XDP_CLASSIFIER=1` in env;
- logs contain `traffic classifier refreshed`;
- `local_asns_enabled`, `local_networks_enabled`, `vlan_map_enabled` are not
  empty or the fallback rule intentionally maps all traffic to `out`;
- BGP table has fresh rows in `bgp_prefix_origin_current`.
