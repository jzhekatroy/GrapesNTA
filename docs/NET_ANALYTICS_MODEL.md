# Network Analytics Model

## Overview

Network Analytics classifies provider traffic using L3 prefix roles, L2 VLAN
attachments, and BGP origin ASN enrichment. Direction is computed in
`xdpflowd` and written into `default.flows_raw`.

## Entities

Table: `default.net_entities`

- `entity_id` — stable identifier (`customer:iconnet`, `uplink:retn`)
- `display_name` — human-readable label
- `enabled` — soft delete via ReplacingMergeTree

View: `default.net_entities_enabled`

## Flow Sources

Table: `default.net_flow_sources`

- `source_id` — logical traffic observation point (`xdp-core-mirror-1`)
- `source_type` — `xdp`, `dns`, `netflow`, `ipfix`, `sflow`, `manual`
- `include_in_total` — whether dashboard totals include this source
- `enabled` — soft delete via ReplacingMergeTree

View: `default.net_flow_sources_enabled`

Raw tables carry only `source_id`. Metadata lives in `net_flow_sources`.

## L3 Prefixes

Table: `default.net_l3_prefixes`

Roles:

| Role | Meaning |
|------|---------|
| `provider_public` | Provider-owned public address space |
| `internal` | Provider internal infrastructure |
| `customer_allocated` | Prefix allocated to a customer |
| `customer_transit` | Customer-owned prefix announced through provider |

| Field | Meaning |
|-------|---------|
| `origin_asn` | Operator-declared origin ASN for this prefix. Used by `xdpflowd` when BMP does not export locally originated routes. `0` = fall back to BGP lookup. |

View: `default.net_l3_prefixes_enabled`

ASN resolution order for a matched L3 prefix:

1. `origin_asn` from `net_l3_prefixes` when non-zero
2. otherwise BGP origin ASN from `bgp_prefix_origin_current`
3. otherwise `0`

## L2 VLANs

Table: `default.net_l2_vlans`

Attachment types: `customer`, `uplink`, `ix`, `peering`, `core`, `internal`,
`unknown`.

Boundary: `internal`, `external`, `unknown`.

View: `default.net_l2_vlans_enabled`

## Direction Rules

`local-or-customer` means any L3 role except `remote`.

| Source | Destination | Direction |
|--------|-------------|-----------|
| local-or-customer | external (`remote`) | `out` |
| external | local-or-customer | `in` |
| local-or-customer | local-or-customer | `internal` |
| external | external | `transit` |
| not classified | any | `unknown` |

If no L3 prefixes are configured, direction stays `unknown`.

## flows_raw Columns

New columns written by classifier:

- `src_role`, `dst_role`
- `src_entity`, `dst_entity`
- `source_id` — logical observation point (see `net_flow_sources`)

Existing enrichment columns remain populated for compatibility:

- `direction`
- `src_attachment_*`, `dst_attachment_*`
- `src_network_role`, `dst_network_role`

## Aggregates

Production ingest does **not** use sync materialized views on `flows_raw`.
Aggregate tables are filled asynchronously on the collector by
`scripts/traffic_rollup_async.py` (systemd `traffic-rollups.timer`), with
progress tracked in `default.traffic_rollup_state`. Expected UI lag: 5–10 minutes.
See [`CLICKHOUSE_DB_SETUP_RUNBOOK.md`](CLICKHOUSE_DB_SETUP_RUNBOOK.md) §7.

| Table | Purpose |
|-------|---------|
| `traffic_direction_1m` | bytes/packets/flows by source + direction |
| `traffic_role_1m` | by source + L3 role |
| `traffic_entity_1m` | by source + entity |
| `traffic_vlan_1m` | by source + VLAN attachment |
| `traffic_protocol_1m` | by source + IP protocol number + direction |
| `traffic_service_1m` | by source + service inferred from transport + port |
| `traffic_unknown_port_1m` | by source + unknown service port for `other` drill-down |
| `traffic_country_1m` | by source + country basis/side + direction for heatmaps |
| `traffic_talker_1m` | by source + endpoint side (`src`/`dst`) + endpoint for top talkers |
| `traffic_pair_1m` | by source + `src_ip -> dst_ip` pair for top talker pairs |
| `traffic_talker_1h` | hourly rollup of `traffic_talker_1m` for multi-hour top talkers |
| `traffic_pair_1h` | hourly rollup of `traffic_pair_1m` for multi-hour top pairs |
| `traffic_dashboard_1m` | pivot dashboard (minute, source) |
| `traffic_dashboard_1h` | pivot dashboard (hour, source) |
| `traffic_dashboard_1d` | pivot dashboard daily totals for month+ windows |

`traffic_protocol_1m.proto` keeps the raw IP protocol number from
`flows_raw.proto`. UI/API code should map common values such as `6=TCP`,
`17=UDP`, `1=ICMP`, `58=ICMPv6`, `47=GRE`, `50=ESP`, and show unknown or rare
values as `IP-<number>`.

`traffic_service_1m` is a separate application/service aggregate based on
`port_services`. It answers a different UI question than `traffic_protocol_1m`:
`traffic_protocol_1m` shows TCP/UDP/GRE/ESP, while `traffic_service_1m` shows
HTTPS/NTP/DNS/SSH and service categories.

`traffic_unknown_port_1m` stores only flows where neither source nor destination
port matched `port_services`. The UI uses it for the "Other" service slice
drill-down to TOP ports without scanning `flows_raw`.

`traffic_country_1m` stores minute buckets with four country dimensions per flow
minute aggregate input: IP-country and ASN-country, each on `src` and `dst`
sides. The UI maps rows to a single country per flow using `remote` (default),
`src`, or `dst` map modes. Use `country_basis = 'ip'` for geographic prefix
country (default heatmap) and `country_basis = 'asn'` for ASN registry country.

`traffic_talker_1m` stores source and destination endpoints as separate rows for
top-talker tables. `endpoint_side = 'src'` powers "Sources", while
`endpoint_side = 'dst'` powers "Destinations". Rows include endpoint IP, ASN
name/number, IP country, ASN country, scope, label, network name/role, bytes,
packets, and flow count. Minute top-talker aggregates have TTL 2 days and are
intended for near-real-time / up-to-1h UI windows.

`traffic_pair_1m` stores `src_ip -> dst_ip` pairs with both endpoint ASN/country
attributes. It powers the "Pairs" tab without scanning `flows_raw`. Pair
cardinality is high, so minute pairs also have TTL 2 days.

`traffic_talker_1h` and `traffic_pair_1h` roll up the minute top-talker tables
to hour buckets and keep 90 days. UI should use them for 3h/6h/12h/24h windows
and longer pair views.

`traffic_dashboard_1d` stores daily totals only. Use it for long-window total
traffic and average speed. Query `traffic_dashboard_1h` (or `1m` for exact
minute-level peaks) when the UI needs a meaningful `max_gbps` value.

## Async Reports

Table: `default.net_reports`

Statuses: `queued`, `running`, `completed`, `failed`.

Types:

- `top_bytes` — top entities/roles/VLANs by bytes
- `direction_summary` — bytes by direction

## UI / API

UI is built on Laravel + MoonShine in a separate repository. MoonShine
resources operate directly on ClickHouse tables and views described
above. Query templates for dashboard widgets live in
`docs/UI_CLICKHOUSE_QUERIES.md`.

- `net_entities` + `net_entities_enabled` — entity registry resource.
- `net_l3_prefixes` + `net_l3_prefixes_enabled` — L3 prefix resource.
- `net_l2_vlans` + `net_l2_vlans_enabled` — L2 VLAN resource.
- `traffic_dashboard_1m` / `traffic_dashboard_1h` / `traffic_dashboard_1d` —
  pivoted dashboard.
- `traffic_direction_1m`, `traffic_role_1m`, `traffic_entity_1m`,
  `traffic_vlan_1m`, `traffic_protocol_1m`, `traffic_service_1m`,
  `traffic_unknown_port_1m`, `traffic_country_1m`, `traffic_talker_1m`,
  `traffic_pair_1m`, `traffic_talker_1h`, `traffic_pair_1h` — drill-down series.
- `net_reports` — async report queue.

Writes go through INSERTs into the base `ReplacingMergeTree` tables
with `updated_at = now()`; soft-delete is `enabled = 0`.

## Environment

xdpflowd:

```env
XDP_CLASSIFIER=1
XDP_CLASSIFIER_L3_PREFIXES_VIEW=default.net_l3_prefixes_enabled
XDP_CLASSIFIER_L2_VLANS_VIEW=default.net_l2_vlans_enabled
```

ClickHouse credentials for MoonShine/Laravel are configured in the
MoonShine app's `.env`.
