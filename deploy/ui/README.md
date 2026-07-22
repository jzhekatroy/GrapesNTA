# grapes-nta (UI)

NTAdmin UI vendored into GrapesNTA for server deploys **without** access to the
private `mavotronik/NTAdmin` repo.

```text
deploy/ui/
  app/                 # UI sources (package.json, server/, public/, Dockerfile)
  docker-compose.yml   # host network, port 3000
  env.example          # secrets template
  SOURCE.txt           # last sync commit from NTAdmin
```

## Deploy on the server

```bash
cd /opt/GrapesNTA
./deploy/deploy.sh ui
```

First run copies `/opt/grapes/ui/.env` → `deploy/ui/.env` if missing, and keeps
data at `/opt/grapes/ui/data` (`UI_DATA_DIR`).

## Refresh sources from NTAdmin (dev machine)

When you need the latest fixes from the private UI repo:

```bash
# from a local NTAdmin checkout (default: ../NTAdmin)
./scripts/sync-ui-from-ntadmin.sh

# or explicit path / clone URL
./scripts/sync-ui-from-ntadmin.sh /path/to/NTAdmin
NTADMIN_GIT_URL=https://github.com/mavotronik/NTAdmin.git ./scripts/sync-ui-from-ntadmin.sh --clone

git add deploy/ui
git commit -m "Sync UI from NTAdmin"
git push
```

Then on the server: `./deploy/deploy.sh ui`.
