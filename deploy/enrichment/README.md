# grapes-enrichment

Docker service for **slow / external enrichment** (hours–days):

- `geoloaderd` — FTP RIR → `geo_prefix_country` + `asn_registry` (daily)
- `bgp-origin-refresh` — BMP events → `bgp_prefix_origin_current` (every 5 min)
- `asn-names-loader` — Team Cymru → `asn_names` (weekly)
- `snmp-iface-sync` — SNMP v2c poll of sFlow exporters → `net_snmp_agents` /
  `net_interfaces` catalog for Explorer interface names (every ~1 min; no-op
  until agents are enabled and a community is set on the UI SNMP page)

SNMP needs host network reachability to switch mgmt IPs (UDP/161); this
container already runs `network_mode: host`. Community and intervals are read
from CH `net_snmp_settings`, not from `.env`. See `docs/SNMP_INTERFACES_RUNBOOK.md`.

Scheduler: Python `scheduler.py` inside the container (not systemd, not supercronic).
ClickHouse access: HTTP shim (`clickhouse-client-http.sh`) on `:8123` — native
client packages often SIGILL on older CPUs.

Job status (for UI Diagnostics → grapes-enrichment) is written to
`enrichment_job_status` by `bin/run_job.sh` / `bin/report_job_status.py`
(status, exit_code, duration, message, log_tail).

Replaces host `geoloaderd.timer`, `bgp-origin-refresh.timer`, `asn-names-loader.timer`, `snmp-iface-sync.timer`.

Fast rollups + observations live in [`../worker/`](../worker/).

## Deploy

On the server (preferred):

```bash
cd /opt/GrapesNTA
./deploy/deploy.sh enrichment      # git pull + rebuild grapes-enrichment
./deploy/deploy.sh                 # worker + enrichment
./deploy/deploy.sh logs enrichment
```

First install / manual:

```bash
cd /opt/GrapesNTA
git pull

cd deploy/enrichment
cp -n env.example .env
# fill passwords (GEOLOADERD_CH_PASSWORD, BGPORIGIN_CH_PASSWORD, …)

mkdir -p logs
docker compose up -d --build
docker logs --tail 80 -f grapes-enrichment
```

First bgp-origin run may take minutes after BMP peers are online. Raise `BGPORIGIN_MIN_PREFIXES` after full RIB is stable.

## Cutover from host timers

1. Start `grapes-enrichment` and verify CH tables refresh.
2. `systemctl disable --now geoloaderd.timer bgp-origin-refresh.timer asn-names-loader.timer snmp-iface-sync.timer`

## Rollback

```bash
docker compose down
systemctl enable --now geoloaderd.timer bgp-origin-refresh.timer asn-names-loader.timer snmp-iface-sync.timer
```

## Locks

- Full RIR download holds `/tmp/enrichment-heavy.lock`; bgp-origin skips that cycle if geo is running.
- Do not run host systemd enrichment and this container at the same time.
