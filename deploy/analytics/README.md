# Observations analytics worker

Самодостаточный воркер **внутри GrapesNTA** (не нужен clone `mavotronik/NTAdmin`).

Пишет:
- `observation_rollups_5m` (live catch-up)
- due report snapshots
- ensure `observations` / `observation_runs` в ClickHouse

Исходники: `deploy/analytics/server/*` (снимок логики из NTAdmin). UI по-прежнему в NTAdmin и читает те же таблицы CH.

## Деплой на netflow-test / CH-хост

```bash
cd /opt/GrapesNTA
git fetch origin
git checkout feature/observations-analytics
git pull

cd deploy/analytics
cp env.example .env
# заполнить CLICKHOUSE_* (HTTP URL, write user)

mkdir -p data
chown -R 1001:1001 data   # uid контейнера

docker compose up -d --build
docker logs -f grapes-analytics
```

Ожидай: `analytics started`, затем `analytics tick`.

## Без Docker (systemd)

```bash
cd /opt/GrapesNTA/deploy/analytics
npm ci --omit=dev
cp env.example .env   # заполнить

# unit: deploy/systemd/grapes-analytics.service
# поправь WorkingDirectory=/opt/GrapesNTA/deploy/analytics
sudo systemctl enable --now grapes-analytics
```

## Важно

- На одном CH не запускай два воркера сразу (Mac + сервер) — будут гонки по cursor.
- После переноса на сервер останови локальный: `pkill -f 'server/analytics.js'`.
