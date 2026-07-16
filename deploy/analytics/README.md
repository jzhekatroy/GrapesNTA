# Observations analytics worker (у ClickHouse)

Воркер **не** входит в бинарь GrapesNTA: код в [NTAdmin](https://github.com/mavotronik/NTAdmin) (`server/analytics.js`).  
Здесь — деплой рядом с ClickHouse (как `traffic-rollups`).

Делает:
- catch-up `observation_rollups_5m`
- due report snapshots
- ensure таблиц `observations` / `observation_runs` (definitions уже в CH)

UI (`grapes-nta`) может крутиться на другом хосте — definitions общие через ClickHouse.

## Вариант A — Docker (предпочтительно)

На хосте с ClickHouse:

```bash
cd /opt/GrapesNTA
git pull

sudo mkdir -p /opt/NTAdmin/server/data
sudo chown -R 1001:1001 /opt/NTAdmin/server/data

cd deploy/analytics
cp env.example .env
# заполнить CLICKHOUSE_* (write-доступ!) и CH_COL_* как в проде

docker compose up -d --build
docker logs -f grapes-analytics
```

Проверка:

```bash
docker logs --tail 50 grapes-analytics | grep -E 'analytics started|analytics tick|Observations store'
```

## Вариант B — systemd + git clone NTAdmin

```bash
# 1) код UI/worker
sudo git clone https://github.com/mavotronik/NTAdmin.git /opt/NTAdmin
cd /opt/NTAdmin && sudo git pull
cd /opt/NTAdmin && sudo npm ci --omit=dev

# 2) env
sudo cp /opt/GrapesNTA/deploy/analytics/env.example /opt/NTAdmin/.env
sudoedit /opt/NTAdmin/.env

# 3) user
sudo useradd -r -s /usr/sbin/nologin nta 2>/dev/null || true
sudo chown -R nta:nta /opt/NTAdmin

# 4) unit из GrapesNTA
sudo mkdir -p /etc/grapesnta
sudo cp /opt/GrapesNTA/deploy/systemd/grapes-analytics.env.example /etc/grapesnta/grapes-analytics.env
sudo cp /opt/GrapesNTA/deploy/systemd/grapes-analytics.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now grapes-analytics
sudo journalctl -u grapes-analytics -f
```

## DDL (опционально вручную)

Обычно worker/UI создают таблицы сами. Вручную:

```bash
clickhouse-client --multiquery < /opt/GrapesNTA/deploy/clickhouse/observations_store.sql
```

## После деплоя

1. На сервере UI должен быть **свежий NTAdmin** (`main` с CH-store наблюдений) — иначе UI всё ещё смотрит в пустой JSON.
2. Список наблюдений общий через `default.observations` — копировать JSON не нужно.
3. Артефакты отчётов (HTML/CSV) пишутся в `NTADMIN_DATA_DIR`; для скачивания с UI этот volume должен быть доступен UI **или** отчёты смотрят только локально на CH-хосте.
