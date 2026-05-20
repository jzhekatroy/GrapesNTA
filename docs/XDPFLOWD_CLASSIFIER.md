# xdpflowd classifier: Attachment + Endpoint

`xdpflowd` can enrich every ClickHouse flow row before insert. The goal is to
avoid heavy dashboard queries over `flows_raw`.

## Data Sources

The classifier refreshes these ClickHouse views/tables into memory:

- `default.bgp_prefix_origin_current`: BGP prefix -> origin ASN.
- `default.vlan_map_enabled`: outer VLAN -> attachment kind/boundary/label/operator.
- `default.local_asns_enabled`: ASNs treated as local endpoint ownership.
- `default.local_networks_enabled`: prefixes treated as local/customer endpoint ownership.

The classifier deliberately separates two concepts:

```text
VLAN attachment: where the packet was seen
Endpoint scope:  who owns the IP address
```

Direction is derived from endpoint scope, not directly from VLAN.

MVP decisions:

- VLAN id is global, not scoped by sampler/interface.
- Only the outer VLAN tag is used.
- Private ASNs are not local by default. Add them explicitly to `local_asns`.
- `transit` is one category for external -> external.
- `src_kind` / `dst_kind` are kept as physical columns but new rows fill them
  with endpoint scope (`local`, `customer`, `remote`, `unknown`). Use the
  explicit `src_endpoint_*` and `src_attachment_*` columns in new UI/API code.

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
- `src_attachment_kind` / `dst_attachment_kind`: VLAN/link type, e.g.
  `customer`, `uplink`, `core`, `internal`, `mgmt`, `ix`, `peering`, `unknown`.
- `src_attachment_boundary` / `dst_attachment_boundary`: `internal`,
  `external`, `unknown`.
- `src_attachment_label` / `dst_attachment_label`: VLAN/link label.
- `src_attachment_operator` / `dst_attachment_operator`: stable operator id for
  the VLAN/link.
- `src_endpoint_scope` / `dst_endpoint_scope`: IP ownership relative to us:
  `local`, `customer`, `remote`, `unknown`.
- `src_endpoint_source` / `dst_endpoint_source`: why scope was chosen:
  `asn`, `prefix`, `fallback`, `unknown`.
- `src_network_name` / `dst_network_name`: local prefix name when matched.
- `src_network_role` / `dst_network_role`: local prefix role when matched.
- `src_kind` / `dst_kind`: compatibility columns, now filled with endpoint scope.
- `src_label` / `dst_label`: compatibility endpoint label.
- `src_operator` / `dst_operator`: compatibility endpoint operator id.
- `src_vlan` / `dst_vlan`: current XDP path writes outer VLAN to `src_vlan`;
  `dst_vlan` stays `0` until an exporter supplies separate destination VLAN.

## Direction Rules

The classifier has three stages.

### Stage 1: attachment classification from VLAN

For each side (`src` and `dst`) `xdpflowd` first maps VLAN to attachment
metadata. This describes the link/context where the packet was observed. It
does **not** decide IP ownership.

| VLAN map column | Flow columns | Meaning |
|-----------------|--------------|---------|
| `attachment_kind` | `src_attachment_kind` / `dst_attachment_kind` | Link type: `customer`, `uplink`, `core`, `internal`, `mgmt`, `ix`, `peering`, `unknown`. |
| `boundary` | `src_attachment_boundary` / `dst_attachment_boundary` | Link boundary: `internal`, `external`, `unknown`. |
| `label` | `src_attachment_label` / `dst_attachment_label` | Human-readable link name. |
| `operator_id` | `src_attachment_operator` / `dst_attachment_operator` | Stable operator/customer/provider id for the link. |

Examples:

```text
VLAN 210 -> attachment_kind=customer, boundary=internal, label=Iconnet VLAN
VLAN 444 -> attachment_kind=uplink,   boundary=external, label=RETN uplink
VLAN 667 -> attachment_kind=core,     boundary=internal, label=Core VLAN
```

### Stage 2: endpoint classification from IP/ASN/prefix

For source and destination independently, `xdpflowd` decides who owns the IP
address relative to us.

| Priority | Check | Output |
|----------|-------|--------|
| 1 | Origin ASN exists in `default.local_asns_enabled`. | `endpoint_scope='local'`, `endpoint_source='asn'`, label/operator from local ASNs. |
| 2 | IP address matches `default.local_networks_enabled`. | `endpoint_scope='customer'` for role `customer`; `endpoint_scope='local'` for roles `local/internal/mgmt`; `endpoint_source='prefix'`, network name/role from local prefixes. |
| 3 | No local match. | `endpoint_scope='remote'`, `endpoint_source='fallback'`. |
| 4 | Classifier disabled/not loaded or invalid IP version. | `endpoint_scope='unknown'`, `endpoint_source='unknown'`. |

Origin ASN is still written for every endpoint when BGP lookup succeeds. ASN
enrichment (`asn_registry_enriched`, country, RIR, AS name) remains separate
from endpoint scope.

### Stage 3: direction from endpoint scope

```text
no local config                          -> out
src local/customer && dst local/customer -> internal
src local/customer && dst remote         -> out
src remote         && dst local/customer -> in
src remote         && dst remote         -> transit
src unknown or dst unknown               -> unknown
```

Examples:

| Flow facts | Attachment result | Endpoint result | Direction |
|------------|-------------------|-----------------|-----------|
| `src_vlan=444`, `src_ip=8.8.8.8`, `dst_ip` in customer prefix. | `src_attachment_kind=uplink`, `boundary=external`. | `src_endpoint_scope=remote`, `dst_endpoint_scope=customer`. | `in` |
| `src_ip` in local ASN, `dst_ip=8.8.8.8`. | VLAN may be unknown. | `src_endpoint_scope=local`, `dst_endpoint_scope=remote`. | `out` |
| Both IPs are in local/customer prefixes. | Any attachment. | `src_endpoint_scope=customer`, `dst_endpoint_scope=local/customer`. | `internal` |
| Neither IP matches local ASN/prefix. | Any attachment. | `src_endpoint_scope=remote`, `dst_endpoint_scope=remote`. | `transit` |

Operational note: currently the XDP path writes the outer VLAN tag to
`src_vlan`. `dst_vlan` usually stays `0` unless a future exporter supplies a
separate destination/egress VLAN. Therefore destination attachment is often
`unknown`, while destination endpoint classification still works by ASN/prefix.

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
