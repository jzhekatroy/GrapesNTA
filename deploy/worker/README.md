# grapes-worker

Docker service for **periodic CH aggregates** (minute-scale):

- Observations rollup + scheduled reports (Node, long-running)
- Traffic dashboard/direction/… rollups (Python, every minute)
- ASN talkers/pairs rollups (Python, every 5 minutes)
- ERP PiterIX client sync (Node, nightly at 03:15)

Replaces host `grapes-analytics` + `traffic-rollups.timer` + `traffic-talkers-rollups.timer`
+ `erp-piterix-sync.timer`.

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

mkdir -p logs data
# uid 1001 = app user inside grapes-worker; root-owned logs abort rollups
chown -R 1001:1001 logs data

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

## ERP PiterIX nightly sync

`bin/cron-erp-sync.sh` runs the same code as the UI's «Прогон» button
(`analytics/server/erp-piterix-run.js`), just with `trigger=cron`. Consequences
worth knowing:

- The on/off switch and the API token stay in `default.app_erp_sync_settings`,
  edited in the UI. `.env` needs nothing; toggling the checkbox takes effect the
  next night without a restart, and a disabled night is written to
  `erp_piterix_sync_log` as `skipped`.
- Writes go in as `CLICKHOUSE_WRITE_USER` (`ui_admin`), which already holds
  INSERT on `default.*`.
- Schedule is local time, so the container sets `TZ=${WORKER_TZ:-Europe/Moscow}`.
  With an unset TZ the crontab would fire at 06:15 MSK.
- There is no catch-up. If the container was down at 03:15 the run is lost and
  the next one is the following night; trigger it by hand from the UI, or:

```bash
docker exec grapes-worker /app/bin/cron-erp-sync.sh
clickhouse-client -q "SELECT started_at, trigger, status, fetched, active FROM default.erp_piterix_sync_log ORDER BY started_at DESC LIMIT 5 FORMAT PrettyCompact"
```

## Cutover from host timers

Host timers are archived in [`attic/systemd/`](../../attic/systemd/). A new
stand should never enable them: this container is the only rollup writer.

Do **not** run two observation workers or two rollup timers against the same CH.
Same for ERP: if a stand still has the host unit, disable it before deploying
this image, otherwise both write `net_clients` on the same night.

```bash
systemctl disable --now erp-piterix-sync.timer 2>/dev/null || true
```

## Rollback

Re-enabling host `traffic-rollups.timer` is not supported. Restore a previous
`grapes-worker` image/compose instead.