# grapes-worker

Docker service for **periodic CH aggregates** (minute-scale):

- Observations rollup + scheduled reports (Node, long-running)
- Traffic dashboard/direction/… rollups (Python, every minute)
- ASN talkers/pairs rollups (Python, every 5 minutes)

Replaces host `grapes-analytics` + `traffic-rollups.timer` + `traffic-talkers-rollups.timer`.

Enrichment (geo/bgp/asn-names) lives in [`../enrichment/`](../enrichment/).

## Deploy

On the server (preferred):

```bash
cd /opt/GrapesNTA
./deploy/deploy.sh worker          # git pull + rebuild grapes-worker
./deploy/deploy.sh                 # worker + enrichment
./deploy/deploy.sh ui              # grapes-nta (vendored deploy/ui/app)
./deploy/deploy.sh full            # worker + enrichment + ui
./deploy/deploy.sh logs worker     # follow logs
```

UI sources live in `deploy/ui/app` (synced from private NTAdmin via
`scripts/sync-ui-from-ntadmin.sh` on a dev machine).

First install / manual:

```bash
cd /opt/GrapesNTA
git pull

cd deploy/worker
cp -n env.example .env
# fill CLICKHOUSE_* and TRAFFIC_ROLLUP_* passwords
# reuse existing observation data: WORKER_DATA_DIR=/opt/grapes/analytics/data

mkdir -p logs
# if fresh install: mkdir -p data && chown -R 1001:1001 data

docker compose up -d --build
docker logs --tail 80 -f grapes-worker
```

Expect: `grapes-worker: starting observations loop`, then `analytics started` / `analytics tick`.

## Cutover from host timers

1. Start `grapes-worker` and verify rollups + observations.
2. `docker stop grapes-analytics` (or remove container).
3. `systemctl disable --now traffic-rollups.timer traffic-talkers-rollups.timer`

Do **not** run two observation workers or two rollup timers against the same CH.

## Rollback

```bash
docker compose down
systemctl enable --now traffic-rollups.timer traffic-talkers-rollups.timer
cd /opt/grapes/worker/../analytics && docker compose up -d
```
