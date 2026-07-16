# Observations analytics worker (у ClickHouse)

Код воркера: [NTAdmin](https://github.com/mavotronik/NTAdmin) (`server/analytics.js`).  
Этот каталог — только деплой на хосте с доступом к ClickHouse.

## Почему не `docker compose` с git URL

`mavotronik/NTAdmin` — приватный. Анонимный `git clone` в BuildKit падает с
`could not read Username for 'https://github.com'`. Собираем из **локального** `/opt/NTAdmin`.

## Быстрый старт (Docker)

```bash
# 1) NTAdmin на диск (SSH deploy key / gh auth)
sudo mkdir -p /opt
sudo git clone git@github.com:mavotronik/NTAdmin.git /opt/NTAdmin
cd /opt/NTAdmin && sudo git pull && sudo git checkout main

sudo mkdir -p /opt/NTAdmin/server/data
sudo chown -R 1001:1001 /opt/NTAdmin/server/data

# 2) GrapesNTA deploy package
cd /opt/GrapesNTA
git fetch origin
git checkout feature/observations-analytics
git pull

cd deploy/analytics
cp env.example .env
# вписать пароли CLICKHOUSE_* (как у UI)

# 3) build + run
NTADMIN_SRC=/opt/NTAdmin docker compose up -d --build
docker logs -f grapes-analytics
```

Ожидай: `analytics started`, затем `analytics tick`.

## DDL

`clickhouse-client` на `localhost:9000` часто **не** тот CH. Для HTTP-прокси:

```bash
# native, если доступен с хоста (пример порта native proxy):
clickhouse-client --host 95.215.1.30 --port 6124 \
  --user ui_admin --password '***' \
  --multiquery < /opt/GrapesNTA/deploy/clickhouse/observations_store.sql
```

Или пропусти: worker/UI сами делают `CREATE TABLE IF NOT EXISTS`.

Worker ходит в CH по **HTTP** (`CLICKHOUSE_URL=http://…:6123`), не через native 9000.

## systemd (без Docker)

См. `deploy/systemd/grapes-analytics.service` — нужен Node + `npm ci` в `/opt/NTAdmin`.
