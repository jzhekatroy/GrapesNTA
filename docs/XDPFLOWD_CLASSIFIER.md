# xdpflowd classifier: Network Analytics

`xdpflowd` enriches every ClickHouse flow row before insert using the Network
Analytics L3/L2 model.

See also:

- [NET_ANALYTICS_MODEL.md](NET_ANALYTICS_MODEL.md)
- [NET_ANALYTICS_OPERATIONS.md](NET_ANALYTICS_OPERATIONS.md)

## Data Sources

The classifier refreshes these ClickHouse views into memory:

- `default.bgp_prefix_origin_current` — BGP prefix -> origin ASN
- optional `default.ip_asn_prefixes_current` — public IP prefix -> ASN fallback
- `default.net_l3_prefixes_enabled` — L3 prefix roles and entities
- `default.net_l2_vlans_enabled` — VLAN attachment context

```text
L3 role/entity: who owns the IP address
L3 origin_asn:  operator ASN for local/customer prefixes (authoritative when set)
BGP origin ASN: external IP -> ASN from bmp_route_events rebuild
IP->ASN fallback: remote ASN when BMP/BGP is not full-view
L2 attachment:  where the packet was seen (VLAN)
Direction:      derived from L3 roles
```

ASN lookup order:

1. `net_l3_prefixes_enabled.origin_asn` for matched local/customer prefixes
   when non-zero.
2. `bgp_prefix_origin_current` from BMP/BGP.
3. Optional `ip_asn_prefixes_current` fallback, loaded from public IP→ASN
   snapshots.
4. `0` when no source has a match.

This keeps operator-owned space authoritative while still filling remote ASN
when BMP does not provide a full view. If the fallback is not configured,
remote IPs rely only on `bgp_prefix_origin_current`.

## L3 Roles

| Role | Scope written to legacy columns |
|------|--------------------------------|
| `provider_public` | `local` |
| `internal` | `local` |
| `customer_allocated` | `customer` |
| `customer_transit` | `customer` |
| unmatched | `remote` |

## Direction Rules

| Source role | Destination role | Direction |
|-------------|------------------|-----------|
| local-or-customer | remote | `out` |
| remote | local-or-customer | `in` |
| local-or-customer | local-or-customer | `internal` |
| remote | remote | `transit` |

If no L3 prefixes are configured, every address falls back to role `remote`,
so direction is **`transit`** (not `unknown`). `unknown` means the classifier
could not classify the endpoints (disabled / unparseable), not “catalog empty”.

The table above applies while `net_direction_settings_current.direction_mode` is
`prefixes`. In mode `ports` the direction comes from the manually marked sides of
the ingress and egress ports instead, and every other enrichment column is still
filled from prefixes. The mirror path carries no ifIndex, so `xdpflowd` writes
`unknown` in that mode; see
[PORT_BOUNDARY_DIRECTION.md](PORT_BOUNDARY_DIRECTION.md).

## Required DDL

Apply after cleanup of legacy tables:

```bash
clickhouse-client ... --multiquery < deploy/clickhouse/cleanup_old_classification.sql
clickhouse-client ... --multiquery < deploy/clickhouse/flows_raw_extensions.sql
clickhouse-client ... --multiquery < deploy/clickhouse/ip_asn_prefixes.sql   # optional remote ASN fallback
clickhouse-client ... --multiquery < deploy/clickhouse/net_entities.sql
clickhouse-client ... --multiquery < deploy/clickhouse/net_l3_prefixes.sql
clickhouse-client ... --multiquery < deploy/clickhouse/net_l2_vlans.sql
clickhouse-client ... --multiquery < deploy/clickhouse/traffic_direction_1m.sql
clickhouse-client ... --multiquery < deploy/clickhouse/traffic_role_1m.sql
clickhouse-client ... --multiquery < deploy/clickhouse/traffic_entity_1m.sql
clickhouse-client ... --multiquery < deploy/clickhouse/traffic_vlan_1m.sql
clickhouse-client ... --multiquery < deploy/clickhouse/traffic_dashboard_1m.sql
clickhouse-client ... --multiquery < deploy/clickhouse/traffic_rollup_state.sql
clickhouse-client ... --multiquery < deploy/clickhouse/detach_traffic_mvs.sql
```

`traffic_*.sql` create aggregate tables only (no sync MV). Enable async rollups on
the collector: [`CLICKHOUSE_DB_SETUP_RUNBOOK.md`](CLICKHOUSE_DB_SETUP_RUNBOOK.md) §7.

## Runtime Config

In `/etc/xdpflowd/xdpflowd.env`:

```bash
XDP_CLASSIFIER=1
XDP_CLASSIFIER_REFRESH=60s
XDP_CLASSIFIER_BGP_TABLE=default.bgp_prefix_origin_current
# Optional; set only after loading deploy/clickhouse/ip_asn_prefixes.sql.
XDP_CLASSIFIER_IP_ASN_TABLE=default.ip_asn_prefixes_current
XDP_CLASSIFIER_L3_PREFIXES_VIEW=default.net_l3_prefixes_enabled
XDP_CLASSIFIER_L2_VLANS_VIEW=default.net_l2_vlans_enabled
```

CLI equivalent:

```bash
./bin/xdpflowd \
  ... \
  -ch-dsn 'clickhouse://USER:PASS@HOST:9000/default' \
  -ch-table default.flows_raw \
  -classifier \
  -classifier-refresh 60s \
  -classifier-ip-asn-table default.ip_asn_prefixes_current \
  -classifier-l3-prefixes-view default.net_l3_prefixes_enabled \
  -classifier-l2-vlans-view default.net_l2_vlans_enabled
```

## Written Columns

Primary new columns:

- `src_role`, `dst_role` — L3 role
- `src_entity`, `dst_entity` — entity id from L3 prefix or VLAN

Compatibility columns still populated:

- `direction`
- `src_asn`, `dst_asn`
- `src_attachment_*`, `dst_attachment_*`
- `src_endpoint_scope`, `dst_endpoint_scope`
- `src_network_role`, `dst_network_role`

## Verification

Classifier refresh log:

```text
traffic classifier refreshed bgp_prefixes=N ip_asn_prefixes=P l3_prefixes=M vlans=K has_local_config=true
```

Recent enriched rows:

```sql
SELECT
  toString(time_received_ns) AS ts,
  direction,
  src_role,
  dst_role,
  src_entity,
  dst_entity,
  src_vlan,
  src_attachment_kind
FROM default.flows_raw
WHERE time_received_ns > now() - INTERVAL 5 MINUTE
ORDER BY time_received_ns DESC
LIMIT 20;
```

Aggregate freshness:

```sql
SELECT max(minute) AS latest FROM default.traffic_dashboard_1m;
SELECT direction, sum(bytes) FROM default.traffic_direction_1m
WHERE minute >= now() - INTERVAL 5 MINUTE
GROUP BY direction;
```

Direction matrix check on production data:

```sql
SELECT
    s.src_role,
    d.dst_role,
    multiIf(
        s.src_role IN ('provider_public', 'internal', 'customer_allocated', 'customer_transit')
            AND d.dst_role IN ('provider_public', 'internal', 'customer_allocated', 'customer_transit'),
            'internal',
        s.src_role IN ('provider_public', 'internal', 'customer_allocated', 'customer_transit')
            AND d.dst_role = 'remote',
            'out',
        s.src_role = 'remote'
            AND d.dst_role IN ('provider_public', 'internal', 'customer_allocated', 'customer_transit'),
            'in',
        'transit'
    ) AS expected_direction,
    if(isNull(a.flows), 'no traffic', a.observed_direction) AS observed_direction,
    ifNull(a.direction_variants, 0) AS direction_variants,
    ifNull(a.flows, 0) AS flows,
    ifNull(a.gbps_5m, 0) AS gbps_5m,
    if(
        isNull(a.flows),
        'not seen',
        if(observed_direction = expected_direction AND direction_variants = 1, 'ok', 'bad')
    ) AS status
FROM
(
    SELECT arrayJoin([
        'remote',
        'provider_public',
        'internal',
        'customer_allocated',
        'customer_transit'
    ]) AS src_role
) AS s
CROSS JOIN
(
    SELECT arrayJoin([
        'remote',
        'provider_public',
        'internal',
        'customer_allocated',
        'customer_transit'
    ]) AS dst_role
) AS d
LEFT JOIN
(
    SELECT
        src_role,
        dst_role,
        any(direction) AS observed_direction,
        countDistinct(direction) AS direction_variants,
        count() AS flows,
        round(sum(bytes) * 8 / 300 / 1000000000, 3) AS gbps_5m
    FROM default.flows_raw
    WHERE time_received_ns >= now() - INTERVAL 5 MINUTE
    GROUP BY
        src_role,
        dst_role
) AS a
ON s.src_role = a.src_role
AND d.dst_role = a.dst_role
ORDER BY
    s.src_role,
    d.dst_role;
```

Expected result:

```text
status = ok       direction matches the classifier rules
status = not seen this role pair had no traffic in the selected window
status = bad      direction mismatch or several directions for one role pair
```

Short mismatch-only check:

```sql
WITH
    src_role IN ('provider_public', 'internal', 'customer_allocated', 'customer_transit') AS src_known,
    dst_role IN ('provider_public', 'internal', 'customer_allocated', 'customer_transit') AS dst_known,
    multiIf(
        src_known AND dst_known, 'internal',
        src_known AND NOT dst_known, 'out',
        NOT src_known AND dst_known, 'in',
        'transit'
    ) AS expected_direction
SELECT
    src_role,
    dst_role,
    direction,
    expected_direction,
    count() AS flows,
    round(sum(bytes) * 8 / 300 / 1000000000, 3) AS gbps_5m
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 5 MINUTE
GROUP BY
    src_role,
    dst_role,
    direction,
    expected_direction
HAVING direction != expected_direction
ORDER BY gbps_5m DESC;
```

Expected result is `0 rows`. This proves that every role pair observed in the
selected production window was mapped to the expected direction.

## Failure Modes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `classifier refresh failed: load L3 prefixes` | view missing | apply `net_l3_prefixes.sql` |
| `has_local_config=false` | no enabled prefixes | insert into `net_l3_prefixes` |
| direction always `unknown` | classifier disabled or empty L3 config | enable classifier, seed prefixes |
| direction always `transit` | prefixes not matching test IPs | verify prefix CIDR coverage |
