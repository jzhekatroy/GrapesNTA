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

Note the service runs in Docker, so `systemctl is-active grapes-worker` reports
`inactive` on a healthy host. Check `docker ps` instead.

## After a ClickHouse outage or a host reboot

The chain is collector spool drain, then rollup catch-up, then graphs. Nothing
here needs a manual step, but the order explains the delay: rollups deliberately
hold their cursor while a collector is still replaying its spool
(`TRAFFIC_ROLLUP_REQUIRE_SPOOL_DRAINED`), because `flows_raw` is incomplete for
recent buckets until the replay ends.

To see where it stands:

```bash
# how far behind the dashboard rollup is (~300-360s is the configured safety lag)
clickhouse-client -q "SELECT max(minute), dateDiff('second', max(minute), now()) FROM default.traffic_dashboard_1m"
clickhouse-client -q "SELECT job, last_bucket, status, last_error FROM default.traffic_rollup_state FINAL ORDER BY job FORMAT PrettyCompact"
docker logs --since 10m grapes-worker 2>&1 | grep -E 'run start|precheck|action=|run complete'
```

`action=hold reason=spool_draining` means it is waiting on purpose.
`action=stop reason=live_wall` means the tick ran out of its time budget and the
next one continues from the same cursor — normal while catching up a long gap.

Every ClickHouse call is bounded (see the hang-containment block in
`env.example`): one request, one query, one tick, plus a `timeout` around each
cron wrapper. This exists because supercronic holds a flock for the whole tick,
so a single unbounded query used to block every later tick until someone
restarted the container.

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
