# Local Networks And Traffic Direction

This document describes how GrapesNTA decides whether traffic is inbound,
outbound, internal or transit.

## Why This Exists

`flows_raw` contains raw flow rows with `src_addr`, `dst_addr`, bytes and
packets. To build an `In/Out bps` chart we need to know which prefixes are ours:

```text
src external, dst local     -> in
src local, dst external     -> out
src local, dst local        -> internal
src external, dst external  -> transit
```

Without local prefixes, the UI can still show total traffic, but honest In/Out
requires `local_networks`.

## Current Local ASN

For the current deployment, `195.2.241.1` resolves through
`bgp_origin_asn_dict` to:

```text
AS34665 PINDC-AS
```

So the first local-network source is all active prefixes in
`default.bgp_prefix_origin_current` where `origin_asn = 34665`, collapsed into a
minimal non-overlapping set.

Observed first load:

```text
raw BGP prefixes: 404
collapsed local_networks: 84
  IPv4: 75
  IPv6: 9
```

## Data Model

DDL: [`deploy/clickhouse/local_networks.sql`](../deploy/clickhouse/local_networks.sql)

- `default.local_networks` - editable local prefix config.
- `default.local_networks_enabled` - effective enabled rows, deduplicated by
  latest `updated_at`.
- `default.local_networks_dict` - `IP_TRIE` dictionary created by
  `scripts/load_local_networks_from_asn.py`.

The table is intentionally editable. MoonShine can later manage it directly:

```text
prefix, family, name, source, enabled, updated_at
```

Examples:

```text
195.2.240.0/23   4   PINDC-AS AS34665   bgp_origin_as34665   1
2a07:a300::/29   6   PINDC-AS AS34665   bgp_origin_as34665   1
```

## Loader From ASN

The loader reads active BGP prefixes for one ASN, collapses them using Python's
`ipaddress.collapse_addresses()`, writes them into `local_networks`, disables
old rows from the same source that disappeared, and reloads the dictionary.

Script:

```text
scripts/load_local_networks_from_asn.py
```

Systemd:

```text
deploy/systemd/local-networks-loader.env.example
deploy/systemd/local-networks-loader.service
deploy/systemd/local-networks-loader.timer
```

Install/update:

```bash
cd /root/GrapesNTA && git pull --ff-only origin feature/dnsflowd-mvp

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' \
  --multiquery < deploy/clickhouse/local_networks.sql

sudo mkdir -p /etc/local-networks-loader
sudo cp deploy/systemd/local-networks-loader.env.example \
  /etc/local-networks-loader/local-networks-loader.env
sudo chmod 0600 /etc/local-networks-loader/local-networks-loader.env
sudo editor /etc/local-networks-loader/local-networks-loader.env

sudo install -m 0644 deploy/systemd/local-networks-loader.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/local-networks-loader.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now local-networks-loader.timer
```

Manual run:

```bash
sudo systemctl start local-networks-loader.service
journalctl -u local-networks-loader -n 80 --no-pager
```

Expected log:

```text
prefixes: raw=404 collapsed=84 disable_old=0 rows_to_insert=84
load_local_networks_from_asn: done
```

## Dictionary Check

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' --query "
SELECT
    dictHas('default.local_networks_dict', tuple(toIPv4('195.2.241.1'))) AS router_is_local,
    dictHas('default.local_networks_dict', tuple(toIPv4('8.8.8.8'))) AS google_is_local
FORMAT PrettyCompactMonoBlock
"
```

Expected:

```text
router_is_local = 1
google_is_local = 0
```

## Traffic Direction Aggregation

`deploy/clickhouse/traffic_1m.sql` now defines `traffic_1m_mv` with
`dictHas('default.local_networks_dict', ...)` checks for IPv4 and IPv6. New
flow rows are classified as:

```text
internal / out / in / transit
```

Apply the new materialized view:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' --query "
DROP TABLE IF EXISTS default.traffic_1m_mv
"

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' \
  --multiquery < deploy/clickhouse/traffic_1m.sql
```

This affects new rows only. Old rows in `traffic_1m` keep their previous
direction (`unknown`) until a backfill is run.

## Backfill Selected History

For a small period, first delete old aggregate rows:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password 'PASSWORD' --query "
ALTER TABLE default.traffic_1m
DELETE WHERE minute >= toDateTime('2026-05-15 10:00:00', 'UTC')
  AND minute <  toDateTime('2026-05-15 11:00:00', 'UTC')
"
```

Then run the backfill template from `deploy/clickhouse/traffic_1m.sql` for the
same window. Do this in small windows, not for months at once.

## API/UI Rule

For the first `Traffic In/Out, bps` dashboard:

```text
in_bps  = direction = 'in'
out_bps = direction IN ('out', 'unknown', 'transit')
```

This preserves the MVP rule: if local networks are not configured yet, all
traffic is shown as outbound/total rather than disappearing from the chart.
