# grapes-enrichment

Docker service for **slow / external enrichment** (hours–days):

- `geoloaderd` — FTP RIR → `geo_prefix_country` + `asn_registry` (daily)
- `bgp-origin-refresh` — BMP events → `bgp_prefix_origin_current` (every 5 min)
- `asn-names-loader` — Team Cymru → `asn_names` (weekly)

Scheduler: Python `scheduler.py` inside the container (not systemd, not supercronic).
ClickHouse access: HTTP shim (`clickhouse-client-http.sh`) on `:8123` — native
client packages often SIGILL on older CPUs.

Replaces host `geoloaderd.timer`, `bgp-origin-refresh.timer`, `asn-names-loader.timer`.

Fast rollups + observations live in [`../worker/`](../worker/).

## Deploy

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
2. `systemctl disable --now geoloaderd.timer bgp-origin-refresh.timer asn-names-loader.timer`

## Rollback

```bash
docker compose down
systemctl enable --now geoloaderd.timer bgp-origin-refresh.timer asn-names-loader.timer
```

## Locks

- Full RIR download holds `/tmp/enrichment-heavy.lock`; bgp-origin skips that cycle if geo is running.
- Do not run host systemd enrichment and this container at the same time.
