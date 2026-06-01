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

View: `default.net_l3_prefixes_enabled`

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

| Table | Purpose |
|-------|---------|
| `traffic_direction_1m` | bytes/packets/flows by source + direction |
| `traffic_role_1m` | by source + L3 role |
| `traffic_entity_1m` | by source + entity |
| `traffic_vlan_1m` | by source + VLAN attachment |
| `traffic_protocol_1m` | by source + IP protocol number + direction |
| `traffic_service_1m` | by source + service inferred from transport + port |
| `traffic_dashboard_1m` | pivot dashboard (minute, source) |
| `traffic_dashboard_1h` | pivot dashboard (hour, source) |

`traffic_protocol_1m.proto` keeps the raw IP protocol number from
`flows_raw.proto`. UI/API code should map common values such as `6=TCP`,
`17=UDP`, `1=ICMP`, `58=ICMPv6`, `47=GRE`, `50=ESP`, and show unknown or rare
values as `IP-<number>`.

`traffic_service_1m` is a separate application/service aggregate based on
`port_services`. It answers a different UI question than `traffic_protocol_1m`:
`traffic_protocol_1m` shows TCP/UDP/GRE/ESP, while `traffic_service_1m` shows
HTTPS/NTP/DNS/SSH and service categories.

## Async Reports

Table: `default.net_reports`

Statuses: `queued`, `running`, `completed`, `failed`.

Types:

- `top_bytes` — top entities/roles/VLANs by bytes
- `direction_summary` — bytes by direction

## UI / API

UI is built on Laravel + MoonShine in a separate repository. MoonShine
resources operate directly on ClickHouse tables and views described
above:

- `net_entities` + `net_entities_enabled` — entity registry resource.
- `net_l3_prefixes` + `net_l3_prefixes_enabled` — L3 prefix resource.
- `net_l2_vlans` + `net_l2_vlans_enabled` — L2 VLAN resource.
- `traffic_dashboard_1m` / `traffic_dashboard_1h` — pivoted dashboard.
- `traffic_direction_1m`, `traffic_role_1m`, `traffic_entity_1m`,
  `traffic_vlan_1m`, `traffic_protocol_1m`, `traffic_service_1m` —
  drill-down series.
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
