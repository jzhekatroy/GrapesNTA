# SNMP interface catalog

`snmp_iface_sync.py` discovers real sFlow exporters from recent `flows_raw`
rows, polls them with SNMP v2c, and maintains a current interface dictionary.
It does not modify `flows_raw` or traffic rollups.

## Prerequisites and DDL

Install the Net-SNMP CLI tools (`snmpget` and `snmpwalk`) on the polling host,
then apply the schema:

```bash
clickhouse-client --host HOST --port 6124 --user USER --password \
  --multiquery < deploy/clickhouse/net_snmp_interfaces.sql
```

The DDL safely seeds one global settings row with an empty community. It does
not overwrite existing settings when re-applied. Configure the global
community through NTAdmin, or insert a newer settings row. For a CLI-only
setup, avoid putting the community in shell history:

```bash
read -rs SNMP_COMMUNITY
export SNMP_COMMUNITY
python3 - <<'PY' | clickhouse-client --host HOST --port 6124 --user USER --password
import os
value = os.environ["SNMP_COMMUNITY"].replace("\\", "\\\\").replace("'", "\\'")
print("""INSERT INTO default.net_snmp_settings
(settings_id, community, port, timeout_ms, retries, discover_lookback_hours,
 refresh_interval_sec, full_walk_interval_sec, enabled)
VALUES ('global', '%s', 161, 2000, 1, 24, 1800, 21600, 1)""" % value)
PY
unset SNMP_COMMUNITY
```

Per-switch rows in `net_snmp_agents` may override `community_override`,
`port_override`, `timeout_ms_override`, and `retries_override`; zero/empty
values inherit the global settings.

The dictionary source uses the local native ClickHouse endpoint
`127.0.0.1:9000` and the `default` user. If that user cannot read the current
view, edit the dictionary `SOURCE(CLICKHOUSE(...))` to use a dedicated
read-only local account before applying the DDL.

## Manual smoke test

First verify discovery without making any SNMP requests:

```bash
python3 scripts/snmp_iface_sync.py \
  --host HOST --port 6124 --user USER --password '...' --discover-only

clickhouse-client --host HOST --port 6124 --user USER --password \
  --query "SELECT switch_ip, source_ids, last_seen_at, last_poll_status FROM default.net_snmp_agents_current ORDER BY last_seen_at DESC"
```

Run one real poll tick after credentials and network ACLs are ready:

```bash
python3 scripts/snmp_iface_sync.py \
  --host HOST --port 6124 --user USER --password '...'

clickhouse-client --host HOST --port 6124 --user USER --password \
  --query "SELECT switch_ip, display_name, last_poll_status, last_poll_error FROM default.net_snmp_agents_current ORDER BY switch_ip"

clickhouse-client --host HOST --port 6124 --user USER --password \
  --query "SELECT switch_ip, if_index, if_name, if_alias, if_speed_bps FROM default.net_interfaces_current ORDER BY switch_ip, if_index LIMIT 50"

clickhouse-client --host HOST --port 6124 --user USER --password \
  --query "SELECT dictGet('default.net_interfaces_dict', 'if_name', tuple(switch_ip, if_index)) FROM default.net_interfaces_current LIMIT 1"
```

The script decodes the two sFlow interface format bits and only accepts format
zero (SNMP ifIndex). New agents are polled in the discovery tick. Existing
agents use `refresh_interval_sec` (default 30 minutes); a full `ifName` walk
runs on `full_walk_interval_sec` (default 6 hours). The `is_new` flag remains
set after polling and is cleared only when an operator acknowledges the device
in NTAdmin.

## systemd

Copy the service, timer, and environment example from `deploy/systemd/`.
After reviewing paths and ClickHouse access:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now snmp-iface-sync.timer
systemctl list-timers snmp-iface-sync.timer
journalctl -u snmp-iface-sync.service -n 100 --no-pager
```

The timer runs every minute. Poll failures are recorded as `timeout`,
`auth_error`, `config_error`, or `error`; the community is never logged.
