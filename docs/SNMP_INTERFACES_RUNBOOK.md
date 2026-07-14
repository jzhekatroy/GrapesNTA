# SNMP interface catalog (GrapesNTA + NTAdmin)

This document describes how sFlow interface enrichment works, how to install
it cleanly, and the pitfalls we already hit in production.

## Goal

sFlow samples carry only numeric interface indexes (`in_if` / `out_if`), not
names like `Ethernet1/1`. SNMP fills a catalog of names; Explorer joins that
catalog when displaying `in_if_name` / `out_if_name`.

`flows_raw` and traffic rollups are never rewritten.

## How it works (simple)

```text
sFlow datagram
  └─ sampler_address  →  switch IP
  └─ in_if / out_if   →  ifIndex (number)
        │
        │  stored in flows_raw as-is
        │
SNMP poller (snmp_iface_sync.py)
  └─ snmpget sysName
  └─ snmpwalk ifName (+ alias/descr/speed)
        │
        ▼
net_snmp_agents     inventory of exporters (enable, status, errors)
net_interfaces      catalog: (switch_ip, if_index) → if_name / alias / …
        │
        ▼
NTAdmin Explorer
  LEFT JOIN net_interfaces_current
  ON switch_ip + decoded ifIndex
  → fields switch_ip, in_if_name, out_if_name
```

Match key: **switch IP + ifIndex**.

sFlow interface values use the RFC 3176 format bits. Only format `0` (plain
SNMP ifIndex) is accepted; the low 30 bits are the index. Many Arista/Cisco
boxes use large ifIndex values (`369098752` = `port-channel1`) — that is normal.

## Components

| Piece | Where | Role |
|---|---|---|
| `scripts/snmp_iface_sync.py` | polling host (e.g. netflow-test) | discover + SNMP poll + write CH |
| `snmp-iface-sync.timer` | same host | every ~1 minute oneshot |
| ClickHouse tables/views | CH server (e.g. 95.215.1.30) | settings, agents, interfaces |
| `net_interfaces_dict` | optional on CH | fast `dictGet` for other tools |
| NTAdmin page **SNMP** | admin UI | settings, enable agents, probe, view ports |
| NTAdmin Explorer | admin UI | JOIN catalog for `*_if_name` |

The poller host must reach **both** switch management IPs (UDP/161) **and**
ClickHouse. Do not put the poller behind a Docker bridge that steals the
management subnet (see pitfalls).

## Data model

- `net_snmp_settings` / `_current` — global community, timeouts, intervals,
  `enabled`, `auto_enable_new_agents` (default **off**).
- `net_snmp_agents` / `_current` — one row per `sampler_address` IP:
  enable flag, overrides, `last_poll_status`, errors, `source_ids`.
- `net_interfaces` / `_current` — SNMP catalog; ReplacingMergeTree keeps the
  latest row per `(switch_ip, if_index)`.
- Optional dictionary `net_interfaces_dict` — same catalog for `dictGet`.

Failed polls **do not delete** catalog rows. UI should keep showing last-known
names (“cache”) when status is timeout/queued.

### Status values (agent)

| Status | Meaning |
|---|---|
| `ok` | last poll succeeded |
| `queued` | operator asked for a poll; waiting for timer |
| `never` | never successfully queued/polled (legacy) |
| `timeout` / `auth_error` / `error` / `config_error` | last attempt failed |

NTAdmin labels (when catalog rows exist): «Идёт опрос», «Недоступен · есть кэш».

### Cadence

| Knob | Default | Meaning |
|---|---|---|
| systemd timer | ~1 min | how often the script starts |
| `refresh_interval_sec` | 1800 | min time between polls of an enabled agent (success **and** failure) |
| `full_walk_interval_sec` | 21600 | full ifName walk; otherwise only known indexes |
| `timeout_ms` / `retries` | 10000 / 2 (tuned) | per SNMP PDU |
| `SNMP_SYNC_MAX_AGENTS` | 25 | max agents polled per tick |

Probe / «Опросить» sets `last_poll_at` to epoch and `last_poll_status=queued`
so the next tick picks the agent up without waiting for `refresh_interval_sec`.

## Install checklist (greenfield)

### 1. ClickHouse schema

```bash
clickhouse-client --host CH_HOST --port 6124 --user USER --password \
  --multiquery < deploy/clickhouse/net_snmp_interfaces.sql
```

Notes:

- Prefer plain `ADD COLUMN` once when upgrading old installs; many CH builds
  do **not** support `ADD COLUMN IF NOT EXISTS`.
- Re-applying the SQL drops/recreates `*_current` views. If a dictionary still
  depends on `net_interfaces_current`, drop/recreate the dictionary after the
  view (or drop the dict first).
- `auto_enable_new_agents` defaults to **0**: new exporters appear in inventory
  but are not polled until enabled in UI (or auto-enable is turned on).

### 2. Optional dictionary (not required for NTAdmin Explorer)

Explorer uses `LEFT JOIN net_interfaces_current` as `ui_read` and does **not**
need `dictGet`.

If you still want the dictionary for other SQL:

```bash
export CH_DICT_USER=ui_admin          # must SELECT net_interfaces_current
export CH_DICT_PASSWORD='...'
# Apply on the CH host via native client (not external :6124 proxy):
./deploy/clickhouse/apply_net_snmp_interfaces_dict.sh

# Then (as a user with GRANT OPTION):
GRANT dictGet ON default.net_interfaces_dict TO ui_read;
```

Never ship `USER default` / empty password on hardened clusters — dictionary
reload will fail with authentication errors and any `dictGet` query breaks.

### 3. Poller host

```bash
# packages
apt-get install -y snmp snmp-mibs-downloader   # snmpget / snmpwalk

cd /opt/GrapesNTA && git pull
sudo mkdir -p /etc/grapesnta
sudo cp deploy/systemd/snmp-iface-sync.env.example /etc/grapesnta/snmp-iface-sync.env
# edit CH host/user/password — separate from NTAdmin credentials is fine
sudo cp deploy/systemd/snmp-iface-sync.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now snmp-iface-sync.timer
```

Smoke:

```bash
set -a; source /etc/grapesnta/snmp-iface-sync.env; set +a
python3 scripts/snmp_iface_sync.py --discover-only --verbose
python3 scripts/snmp_iface_sync.py --verbose
journalctl -u snmp-iface-sync.service -n 50 --no-pager
```

### 4. NTAdmin

- Configure global SNMP community / timeout on page **SNMP**.
- Enable agents (or use «Опросить» / «Опросить всех»).
- Explorer: dimensions `switch_ip`, `in_if_name`, `out_if_name`.
- Display timezone: catalog timestamps are UTC wall-clock in CH; UI converts
  to the selected display timezone.

### 5. Network / ACL

- UDP/161 from poller → switches (same community as UI settings).
- Poller → ClickHouse native port (6124 or 9000 as configured).
- **Do not** let a local Docker network own the switch management prefix
  (we hit `172.18.0.0/16` on `xdpflowd-stack_default` capturing `172.18.19.x`).
  Prefer `docker compose down` (without `-v` unless you intend to wipe volumes)
  or re-address the compose network.
- Verify with the same timeouts the poller uses:

```bash
snmpget -v2c -c public -t 10 -r 2 SWITCH:161 -Oqv 1.3.6.1.2.1.1.5.0
time snmpwalk -v2c -c public -t 10 -r 2 SWITCH:161 -On .1.3.6.1.2.1.31.1.1.1.1 | wc -l
```

## Operational tips

- Long full walks + `max_agents=25` can make a oneshot run longer than the
  timer interval; systemd will start the next run after the previous finishes.
  For first bring-up, enable a few agents, confirm `status=ok`, then enable
  the rest.
- Phase logs (`phase=sysName`, `ifName_walk`, `if_details batch=…`) are always
  at INFO — use them when diagnosing which SNMP step fails.
- After a successful poll, `updated_at` on the agent row uses a **fresh**
  timestamp so it wins over the discover() write from the same run (same-second
  `argMax` ties previously showed «Ожидает опроса» while interfaces existed).
- `is_new` is cleared on successful poll.

## Verification queries

```sql
-- Agents
SELECT switch_ip, display_name, snmp_enabled, last_poll_status,
       last_poll_error, toString(last_poll_at)
FROM default.net_snmp_agents_current
ORDER BY last_poll_status, switch_ip;

-- Catalog size
SELECT switch_ip, count() AS ifaces
FROM default.net_interfaces_current
GROUP BY switch_ip
ORDER BY ifaces DESC;

-- Enrichment vs live flows (same logic as Explorer JOIN)
SELECT
  ifNull(nullIf(i.if_name, ''), '') AS in_if_name,
  count() AS flows
FROM default.flows_raw AS f
LEFT JOIN default.net_interfaces_current AS i
  ON i.switch_ip = /* sampler→IP expression */
     AND i.if_index = bitAnd(toUInt32(f.in_if), 0x3FFFFFFF)
WHERE f.time_received_ns >= now64(9) - INTERVAL 15 MINUTE
GROUP BY in_if_name
ORDER BY flows DESC
LIMIT 20;
```

## Pitfalls (do not repeat)

1. **Dictionary with `default`/empty password** — `dictGet` fails even when
   tables are full. Fix SOURCE credentials + `GRANT dictGet` to UI roles, or
   rely on Explorer JOIN (current NTAdmin).
2. **Docker bridge overlaps mgmt subnet** — SNMP timeouts while `snmpwalk` from
   another path works; check `ip route get SWITCH`.
3. **Short SNMP timeout (2s) on large walks** — sysName OK, walk/details fail;
   use ≥5–10s and retries ≥1–2.
4. **Re-apply DDL while dictionary depends on the view** — drop dict or recreate
   dict after views.
5. **`ADD COLUMN IF NOT EXISTS`** — unsupported on some CH versions; use plain
   `ADD COLUMN` once.
6. **CREATE DICTIONARY via external :6124 proxy** — often rejected; use
   `docker exec … clickhouse-client` on the CH host.
7. **Same-second discover+poll agent rows** — fixed in poller by writing poll
   result with a later `updated_at`; keep the agents_current view’s tuple
   `argMax` (status priority) when recreating views.
8. **Mass-enable before reachability** — floods the timer with timeouts; enable
   gradually or probe one switch first.

## File map

```text
deploy/clickhouse/net_snmp_interfaces.sql       tables + views
deploy/clickhouse/net_snmp_interfaces_dict.sql  optional dictionary template
deploy/clickhouse/apply_net_snmp_interfaces_dict.sh
deploy/systemd/snmp-iface-sync.{service,timer,env.example}
scripts/snmp_iface_sync.py
docs/SNMP_INTERFACES_RUNBOOK.md                 this file
```

NTAdmin (separate repo): page `public/pages/snmp.jsx`, API `server/net-snmp.js`,
Explorer dims in `server/explorer.js` (`switch_ip`, `in_if_name`, `out_if_name`).
