# Установка первого стенда GrapesNTA + UI (сервер `nta`)

Дата: **2026-07-20** (cutover worker/enrichment Docker: **2026-07-21**)  
Хост: **nta** · `5.188.236.212`  
ОС: Debian (Docker CE)  
Git: GrapesNTA `main` → `/opt/GrapesNTA`  
Наблюдение за установкой: `tmux attach -t grapes`

Документ фиксирует **фактический** этап установки на этом сервере (что сделали,
куда положили, какие пароли, какие грабли и фиксы). Для повтора на новом хосте —
использовать как чеклист; секреты на следующем стенде генерировать заново.

---

## 1. Целевая архитектура (как на nta сейчас)

| Слой | Что | Как |
|------|-----|-----|
| Host / systemd | `flowcollectord`, `bmpgrapes` | бинарники из GrapesNTA |
| Docker | ClickHouse | `grapes-clickhouse` |
| Docker | observations + traffic/ASN rollups | **`grapes-worker`** (`deploy/worker`, host network) |
| Docker | geo/RIR, bgp-origin, asn-names | **`grapes-enrichment`** (`deploy/enrichment`, host network) |
| Docker | UI NTAdmin | `grapes-nta` (host network, порт **3000**) |

**Снято с хоста после cutover (2026-07-21):** контейнер `grapes-analytics` и
systemd timers `traffic-rollups`, `traffic-talkers-rollups`, `geoloaderd`,
`bgp-origin-refresh`, `asn-names-loader`. Не включать их параллельно с Docker.

Схема ClickHouse — **универсальная** (flows / DNS / BMP / traffic / observations / RBAC).
Профиль площадки выбирает демоны, не форму БД.

XDP/`dnsflowd` на этом стенде **не ставили** (опционально по площадке).

Firewall: `INPUT` policy **DROP**, SSH только из ipset `ssh`
(`/etc/iptables/rules.v4`, `netfilter-persistent`).  
UI `:3000` открыт **тем же ipset** `ssh` (2026-07-20).  
sFlow `:6343/udp` — **ACCEPT**.  
BMP TCP — порт **как на роутерах** (на nta: **`10179`**, не дефолт `5000`);
лучше allowlist IP пиров BMP, не `0.0.0.0/0`.  
CH `:8123`/`:9000` снаружи по-прежнему закрыты.

> **Критично для ASN в flows:** одного `bmpgrapes` мало. Нужен job
> `bgp-origin` в `grapes-enrichment` → таблица `bgp_prefix_origin_current` →
> classifier читает префиксы. Без этого peers online, а `src_asn`/`dst_asn` = 0.

### Конфигурация и доступы к ClickHouse

Секреты **не** запекаются в образы. Каждый compose читает свой `.env`
(`env_file`). Все Docker-сервисы с `network_mode: host` ходят в CH на
`127.0.0.1` (`:8123` HTTP, native `:9000` с хоста).

| Сервис | Файл env на nta | Как ходит в CH |
|--------|-----------------|----------------|
| UI `grapes-nta` | `/opt/grapes/ui/.env` | HTTP `CLICKHOUSE_URL` / `CLICKHOUSE_*` (`ui_read` / `ui_admin`) |
| Worker `grapes-worker` | `/opt/GrapesNTA/deploy/worker/.env` | Node: `CLICKHOUSE_URL` `:8123`; Python rollups: `TRAFFIC_ROLLUP_CH_*` через HTTP-shim `clickhouse-client` → `:8123` |
| Enrichment `grapes-enrichment` | `/opt/GrapesNTA/deploy/enrichment/.env` | `GEOLOADERD_CH_*`, `BGPORIGIN_CH_*`, asn-names (часто наследует geoloaderd); тот же HTTP-shim |
| ClickHouse | `/opt/grapes/clickhouse/` (compose + users) | сам CH; users/`default`/`ui_*`/`collector_write` |

Шаблоны без секретов: `deploy/worker/env.example`, `deploy/enrichment/env.example`.

На nta `.env` worker/enrichment **собраны** из старых host-файлов
(`/etc/grapesnta/traffic-rollups.env`, `/etc/geoloaderd/…`,
`/etc/bgp-origin-refresh/…`) + UI/analytics env. Host-файлы можно оставить
как бэкап, но timers должны быть disabled.

**Важно при сборке `.env`:** не мержить `env.example` *перед* host-файлами
через «первый ключ побеждает» — в example пустые `*_PASSWORD=`, они
перебьют реальные. Правильно: host/UI секреты первыми, либо явно
перезаписать пароли после merge. Enrichment для `SYSTEM RELOAD DICTIONARY`
обычно нужен user с правами admin/`default` (не только `ui_admin`).

**Почему HTTP-shim:** native `clickhouse-client` на CPU nta даёт SIGILL.
В образах worker/enrichment `/usr/local/bin/clickhouse-client` →
`clickhouse-client-http.sh` (HTTP `:8123`). Cron-обёртки принудительно
выставляют `*_CLICKHOUSE_CLIENT=/usr/local/bin/clickhouse-client`.

---

## 2. Доступ к серверу

| | |
|--|--|
| SSH | `odmen@5.188.236.212` |
| Root | `su -` (пароль у оператора) |
| Общая сессия | `tmux new -s grapes` / `tmux attach -t grapes` |

Рабочие логи установки на хосте (примеры):

```text
/tmp/install-collectors.log
/tmp/fix-worker.log
/tmp/install-ui.log
```

---

## 3. Каталоги на сервере

```text
/opt/grapes/clickhouse/     # docker-compose + .env (CH)
/opt/grapes/schema/         # копия deploy/schema, apply.sh
/opt/grapes/worker/         # grapes-analytics compose + .env + data/
/opt/grapes/ui/             # grapes-nta compose + .env + app/ + data/
/opt/GrapesNTA/             # git clone main, bin/flowcollectord, bin/bmpgrapes
/etc/flowcollectord/        # flowcollectord.env
/etc/bmpgrapes/             # bmpgrapes.env
/etc/grapesnta/             # traffic-rollups*.env
/etc/geoloaderd/            # geoloaderd.env
/usr/local/bin/clickhouse-client  # wrapper → docker exec grapes-clickhouse
```

---

## 4. Учётные записи ClickHouse (этот стенд)

Хранятся в `/opt/grapes/clickhouse/.env` (`chmod 600`).

| User | Password | Назначение |
|------|----------|------------|
| `default` | `chdef_qd8FIx7e0cF2UoB2tHY2NrJ3RPyS` | админ CH / apply schema / loaders |
| `ui_read` | `uiread_3ZhZHXliei65azGwAml7a2z7XgIr` | UI SELECT |
| `ui_admin` | `uiadm_PfgkY0qfMsZEVpjgnN2144FHhtI7` | UI write / analytics worker |
| `collector_write` | `coll_R16eUvNHtKNFW0t9pXAlbvJRgZw8` | flowcollectord / bmpgrapes INSERT |

Проверка:

```bash
curl -u 'default:…' 'http://127.0.0.1:8123/ping'
```

**Важно:** `collector_write` нужен не только `INSERT`, но и **`SELECT`** (классификатор
читает BGP/L3/catalog). После первого bootstrap права догоняли через
`clickhouse-client --multiquery` внутри контейнера.

---

## 5. Этап A — Docker + ClickHouse + схема

1. Установить Docker CE + compose plugin.
2. Разложить compose и `.env` в `/opt/grapes/clickhouse/`.
3. `docker compose up -d` → контейнер `grapes-clickhouse` (HTTP `:8123`, native `:9000`).
4. Распаковать `deploy/schema` в `/opt/grapes/schema/`.
5. Создать app-пользователей CH + grants.
6. Запустить `/opt/grapes/schema/apply.sh` → **70** объектов в `default`.

Источник схемы: дамп с prod CH + нормализация в `GrapesNTA/deploy/schema/`
(коммит вида *Add universal ClickHouse schema dump for fresh installs*).

### Грабли этапа A

1. **HTTP `curl` + multi-statement SQL** — создание пользователей через один
   HTTP POST с несколькими statements на свежем CH может не пройти.
   Фикс: `docker exec -i grapes-clickhouse clickhouse-client --multiquery`.
2. В дампе схемы **не было** `asn_registry_staging` (есть `asn_registry` и
   geo staging). Лоадер RIR падал, пока таблицу не создали вручную
   (см. этап D). Нужно добавить DDL в `deploy/schema/40_enrichment/`.

---

## 6. Этап B — коллекторы (`flowcollectord` + `bmpgrapes`)

В `tmux grapes`:

1. Clone/pull GrapesNTA → `/opt/GrapesNTA` (`main`).
2. Go toolchain, `make` / `go build` → `/opt/GrapesNTA/bin/…`.
3. Unit’ы и env:

   - `/etc/systemd/system/flowcollectord.service`
   - `/etc/flowcollectord/flowcollectord.env`
     - sFlow listen `0.0.0.0:6343`
     - `FC_SFLOW_SOURCE_ID=sflow-default`
     - `FC_COLLECTOR_ID=nta-sflow`
     - DSN: `collector_write@127.0.0.1:9000/default`
     - spool: `/var/lib/flowcollectord/ch-spool`
   - `/etc/systemd/system/bmpgrapes.service`
   - `/etc/bmpgrapes/bmpgrapes.env`
     - `BMP_LISTEN` — **тот же порт, что шлют роутеры**
       (example в репо: `0.0.0.0:5000`; на nta: `0.0.0.0:10179`)
     - events → `bmp_route_events`, peers → `bmp_peers`

4. Firewall: ACCEPT BMP TCP на выбранный порт **с IP пиров** (на nta:
   `.248`/`.250`/… → `:10179`).
5. `systemctl enable --now flowcollectord bmpgrapes`.

### Грабли этапа B

Скрипт установки с `set -e` упал на noop/`cp` вокруг `bmpgrapes-exec.sh`
**до** enable unit’ов. Бинарники уже были собраны — добивали отдельным
finish-скриптом (копирование unit’ов, env, `daemon-reload`, start).

**Порт BMP не совпал с роутерами** (слушали `:5000`, пиры слали на
`:10179`) — peers offline, RIB пустой. Фикс: `BMP_LISTEN=0.0.0.0:10179` +
правило firewall + `systemctl restart bmpgrapes`.

Проверка:

```bash
systemctl is-active flowcollectord bmpgrapes
ss -ulnp | grep 6343
ss -tlnp | grep -E '5000|10179'   # тот порт, что в BMP_LISTEN
clickhouse-client -q "SELECT router_ip, peer_ip, is_up FROM bmp_peers ORDER BY router_ip"
```

---

## 7. Этап C — worker + enrichment (Docker)

Актуальный путь на новых стендах и на nta после cutover. Подробности:
`deploy/worker/README.md`, `deploy/enrichment/README.md`.

### C1. `grapes-worker` (observations + traffic/ASN rollups)

Каталог: `/opt/GrapesNTA/deploy/worker`.

- Node loop: observations / scheduled reports → heartbeat в
  `analytics_worker_status`
- supercronic: traffic dashboard/direction/… **каждую 1m**; ASN talkers/pairs
  **каждые 5m** (`traffic_asn_*` / `traffic_asn_pair_*`, не IP talker/pair)
- data volume: на nta `/opt/grapes/analytics/data` (uid **1001**)
- env: `deploy/worker/.env` (шаблон `env.example`)

```bash
cd /opt/GrapesNTA && git pull
cd deploy/worker
cp -n env.example .env   # заполнить CLICKHOUSE_* / TRAFFIC_ROLLUP_* пароли
mkdir -p logs
# cutover: WORKER_DATA_DIR=/opt/grapes/analytics/data
chown -R 1001:1001 "${WORKER_DATA_DIR:-./data}" logs
docker compose up -d --build
docker logs -f grapes-worker
```

### C2. `grapes-enrichment` (geo / bgp-origin / asn-names)

Каталог: `/opt/GrapesNTA/deploy/enrichment`.

| Job | Интервал | Скрипт |
|-----|----------|--------|
| bgp-origin | ~5 min | `rebuild_bgp_origin_asn.py` |
| geoloaderd (RIR) | ~1 day | `load_rir_geo.py` |
| asn-names | ~7 days | `load_asn_names.py` |

Планировщик: **`scheduler.py`** (не systemd, не supercronic — на nta
supercronic падал с `Failed to fork exec`).  
ClickHouse: HTTP-shim (см. §1).

```bash
cd /opt/GrapesNTA/deploy/enrichment
cp -n env.example .env   # GEOLOADERD_CH_*, BGPORIGIN_CH_* пароли
mkdir -p logs
docker compose up -d --build
docker logs -f grapes-enrichment
# разовый bgp-origin:
docker exec grapes-enrichment /app/bin/cron-bgp-origin.sh
```

Кэш RIR: volume `geoloaderd-cache` → `/var/lib/geoloaderd/cache` в контейнере.

### C3. Host wrapper `clickhouse-client` (для ручных проверок с хоста)

```bash
# /usr/local/bin/clickhouse-client → docker exec -i grapes-clickhouse clickhouse-client "$@"
```

Внутри worker/enrichment свой shim на HTTP `:8123` (native CLI в контейнере
на nta не использовать).

### C4. Cutover с systemd (как сделали на nta)

1. Поднять `grapes-worker` и `grapes-enrichment`, убедиться в логах/smoke.
2. `docker stop grapes-analytics && docker rm grapes-analytics` (если был).
3. `systemctl disable --now traffic-rollups.timer traffic-talkers-rollups.timer \
     geoloaderd.timer bgp-origin-refresh.timer asn-names-loader.timer`

Не гонять host timers и Docker-джобы одновременно на один CH.

### C5. BGP origin — обязательно при BMP

Без job `bgp-origin` peers могут быть online, а ASN в flows = 0.

Проверка после успешного rebuild (RIB уже пришёл):

```bash
docker logs grapes-enrichment --tail 50 | grep bgp-origin
clickhouse-client -q "SELECT count(), max(snapshot_ts) FROM bgp_prefix_origin_current"
# ожидание: count >> 0 (на nta ~1.3M), snapshot свежий
# classifier: bgp_prefixes > 0; доля src_asn!=0 растёт
```

Подробности: `docs/BGP_ORIGIN_ASN_TRAFFIC.md`.

> **Legacy (до cutover):** этап C был `grapes-analytics` + host timers
> (`/etc/grapesnta/…`, `/etc/geoloaderd/…`, `/etc/bgp-origin-refresh/…`).
> Units в `deploy/systemd/` оставлены для rollback / старых площадок.

---

## 8. Этап D — фиксы свежего стенда (worker)

После первого прогона:

| Проблема | Симптом | Фикс |
|----------|---------|------|
| Нет `asn_registry_staging` | `geoloaderd` падает после download RIR | в git: `deploy/schema/40_enrichment/08_asn_registry_staging.sql` |
| Нет `asn_registry_enriched` | `traffic_country_1m` rollup error | в git: `deploy/schema/40_enrichment/09_asn_registry_enriched.sql` |
| Talkers на IP-таблицах | огромный CH / лаг talkers; UI ждёт ASN | jobs → `traffic_asn_*` / `traffic_asn_pair_*`; IP talker/pair DDL deprecated |
| Пустой `flows_raw` | rollups skip / exit 1 из‑за raw lag | в unit добавить `--ignore-raw-lag` к `traffic_rollup_async.py`; для свежего стенда допустимо поднять `TRAFFIC_ROLLUP_MAX_RAW_LAG_SECONDS` |
| Rollups state отстаёт от raw | `traffic_dashboard_1m = 0`, state на старых датах | `traffic_rollup_async.py`: empty bootstrap от `now()-safety_lag`, skip-forward к min(raw); разово: `scripts/nta-unblock-rollups.sh` |
| Geo без ASN | `geo_prefix_country` > 0, `asn_registry` = 0 | после staging — повторный `docker exec grapes-enrichment /app/bin/cron-geoloaderd.sh` |
| BMP online, ASN в flows = 0 | `bgp_prefix_origin_current` пусто / `bgp_prefixes=0` | **проверить** `grapes-enrichment` / `cron-bgp-origin.sh` (этап C5); не путать с «нужен ещё loader» |
| Native clickhouse-client SIGILL | rollups/bgp падают на CLI | HTTP-shim в образе; не ставить bare `CLICKHOUSE_CLIENT=clickhouse-client` без PATH |
| supercronic fork fail (enrichment) | enrichment не стартует jobs | использовать `scheduler.py` (уже в образе) |
| BMP peers offline | listen на `:5000`, роутеры → другой порт | выровнять `BMP_LISTEN` + firewall (этап B) |

Результат после фикса (этот стенд):

```text
geo_prefix_country   ≈ 336546
asn_registry         ≈ 121785
asn_registry_staging   существует
WORKER_FIX_OK
```

Rollups на пустом raw могут отработать частично (`ok` + `skipped` + единичный
`failed` из‑за зависимостей бакетов) — нормально до появления реального sFlow.

### Неклассифицированный трафик и «нет VLAN» (2026-07-20)

Это **не** поломка парсера sFlow.

| Симптом | Причина | Что делать |
|---------|---------|------------|
| `direction = transit` при пустом L3 | нет «своих» сетей → оба конца `remote` | ожидаемо; для in/out завести L3 в UI → «Собственные сети» |
| `direction = unknown` | классификатор выключен / нераспарсенный endpoint | проверить `FC_CLASSIFIER=1` и парсинг sFlow |
| ASN = 0 | нет peers **или** пустой `bgp_prefix_origin_current` (нет timer) | BMP listen/firewall → peers up → **C5** `bgp-origin-refresh`; L3 `origin_asn` — только свои сети |
| В UI «нет VLAN», а в raw VLAN есть | VLAN API молча выкидывал `direction=unknown` из фильтра, хотя роллап его пишет | `VLAN_FLOW_DIRECTIONS` должен включать `unknown` (как у протоколов); роллап — fallback `src_vlan`/`dst_vlan` |
| Пустой `net_l2_vlans` | нет каталога подписей VLAN | UI Settings → VLAN (опционально; без него VLAN id всё равно в raw/rollup) |

Проверка raw:

```bash
clickhouse-client -q "
SELECT direction, count() c,
       countIf(src_vlan!=0 OR dst_vlan!=0) with_vlan
FROM flows_raw
WHERE time_received_ns >= now64(9) - INTERVAL 5 MINUTE
GROUP BY direction"
clickhouse-client -q "SELECT count() FROM net_l3_prefixes_enabled"
clickhouse-client -q "SELECT count(), max(minute) FROM traffic_vlan_1m"
```

### Пустой дашборд при живом sFlow (2026-07-20)

Симптомы: `flows_raw` растёт, `traffic_dashboard_1m = 0`, UI пустой.

Причины и системный фикс:

1. **Каталог источников** — rollups и UI JOIN фильтруют `net_flow_sources_enabled`
   (`include_in_total = 1`). Источник `sflow-default` нужно завести в UI Settings
   **до** появления полезных агрегатов (на nta заведён вручную).
2. **Дыры схемы** — `asn_registry_enriched` и ASN-таблицы talkers/pairs
   (`traffic_asn_*`, `traffic_asn_pair_*`) в `deploy/schema`.
3. **Bootstrap rollups** — при пустом raw старый код стартовал с `now()-7d` и
   молотил пустые минуты; новый `traffic_rollup_async.py` стартует от
   `now()-safety_lag` и делает skip-forward к `min(flows_raw)` для enabled sources.
4. **BGP origin** — если BMP уже льёт, а ASN в UI нулевые: проверить
   `grapes-enrichment` / `bgp_prefix_origin_current`, не только peers.

Разовая разблокировка на хосте:

```bash
# скопировать свежий deploy/schema и scripts из GrapesNTA main, затем:
bash /opt/GrapesNTA/scripts/nta-unblock-rollups.sh
```

Проверка:

```bash
clickhouse-client -q "SELECT count(), max(minute), sum(total_bytes) FROM traffic_dashboard_1m"
clickhouse-client -q "
SELECT m.minute, sum(m.total_bytes) b
FROM traffic_dashboard_1m m
INNER JOIN net_flow_sources_enabled s ON m.source_id = s.source_id
WHERE s.include_in_total = 1
GROUP BY m.minute ORDER BY m.minute DESC LIMIT 10
"
```

---

## 9. Этап E — UI (`grapes-nta`)

Репозиторий NTAdmin на GitHub **приватный** → на сервер передали tarball
исходников (`package.json`, `Dockerfile`, `server/`, `public/`), не `git clone`.

```text
/opt/grapes/ui/
  app/                 # исходники NTAdmin
  docker-compose.yml   # network_mode: host, image grapes-nta:latest
  .env                 # CH ui_read / ui_admin, flows_raw columns
  data/                # volume → /app/server/data (uid 1001)
```

```bash
cd /opt/grapes/ui && docker compose up -d --build
curl -sS http://127.0.0.1:3000/api/health
```

Старт UI создал default admin и RBAC в CH:

| | |
|--|--|
| URL | `http://5.188.236.212:3000` |
| Логин | `admin` / `adminadmin` |
| Health | `{"ok":true,"clickhouse":{"connected":true,…}}` |

**Сразу сменить пароль admin.**

Маркер успеха в логе установки: `UI_OK`.

---

## 10. Порты (что слушает стенд)

| Порт | Сервис |
|------|--------|
| 8123 / 9000 | ClickHouse (HTTP / native) |
| 3000 | UI grapes-nta |
| 6343/udp | sFlow → flowcollectord |
| **10179**/tcp | BMP → bmpgrapes (**nta**; сверять с роутерами; не слепо `:5000`) |

---

## 11. Быстрая проверка после установки

```bash
tmux attach -t grapes   # опционально

docker ps --format 'table {{.Names}}\t{{.Status}}'
# grapes-clickhouse, grapes-worker, grapes-enrichment, grapes-nta

systemctl is-active flowcollectord bmpgrapes
# host rollup/enrichment timers должны быть disabled:
systemctl is-enabled traffic-rollups.timer traffic-talkers-rollups.timer \
  geoloaderd.timer bgp-origin-refresh.timer asn-names-loader.timer 2>&1 || true

clickhouse-client -q "SELECT count() FROM system.tables WHERE database='default'"
clickhouse-client -q "SELECT count() FROM geo_prefix_country"
clickhouse-client -q "SELECT count() FROM asn_registry"
clickhouse-client -q "SELECT count() FROM flows_raw"
clickhouse-client -q "SELECT countIf(is_up=1) FROM bmp_peers"
clickhouse-client -q "SELECT count(), max(snapshot_ts) FROM bgp_prefix_origin_current"
clickhouse-client -q "SELECT worker_id, last_heartbeat_at FROM analytics_worker_status ORDER BY last_heartbeat_at DESC LIMIT 3"
clickhouse-client -q "SELECT count(), max(minute) FROM traffic_dashboard_1m WHERE minute >= now()-INTERVAL 2 HOUR"

curl -sS http://127.0.0.1:3000/api/health | head -c 200; echo
```

Ожидание до подачи трафика: `flows_raw = 0`. После направления sFlow на
`:6343` — рост `flows_raw`, затем заполнение traffic rollups.  
После BMP + первого успешного `bgp-origin` в enrichment:
`bgp_prefix_origin_current` > 0, в свежих flows появляется ненулевой ASN.

### Чеклист «BMP + ASN enrichment» (не пропускать)

- [ ] `BMP_LISTEN` = порт на роутерах; firewall allowlist пиров
- [ ] `bmpgrapes` active; `bmp_peers` с `is_up=1`; растут `bmp_route_events`
- [ ] `grapes-enrichment` Up; в логах `bgp-origin: exit=0`
- [ ] `bgp_prefix_origin_current` count ≫ 0, `snapshot_ts` свежий
- [ ] Classifier: `bgp_prefixes` > 0; доля `src_asn!=0 OR dst_asn!=0` в свежем raw растёт
- [ ] `grapes-worker` крутит **ASN** talkers jobs, не IP `traffic_talker_*`
- [ ] Host enrichment/rollup timers **disabled** (нет двойного прогона)

---

## 12. Известные долги / следующие шаги

- [x] Добавить `asn_registry_staging` + `asn_registry_enriched` + talker/pair в `deploy/schema`
- [x] Rollups: empty bootstrap + skip-forward в `traffic_rollup_async.py`
- [x] UI `:3000` — ACCEPT из ipset `ssh` (persist в `/etc/iptables/rules.v4`)
- [x] BMP listen/firewall выровнять с роутерами (`:10179` на nta)
- [x] Обязательный bgp-origin (иначе ASN в flows = 0) — теперь в `grapes-enrichment`
- [x] Talkers/pairs: ASN-only jobs; IP talker/pair таблицы сняты с прода
- [x] Cutover: `grapes-worker` + `grapes-enrichment` вместо analytics + host timers
- [x] HTTP clickhouse-client shim (SIGILL native CLI на nta)
- [ ] CH `:8123`/`:9000` снаружи не открывать (сейчас DROP)
- [ ] Сменить пароль UI `admin`
- [ ] Дожать BMP с роутеров `.251` / `.252` (router-side)
- [ ] Опционально: после стабильного RIB поднять `BGPORIGIN_MIN_PREFIXES`
- [ ] Опционально: loader `ip_asn_prefixes` (asn-names уже в enrichment)
- [ ] При необходимости: SNMP / XDP / dnsflowd по профилю площадки

---

## 13. Соответствие локальным скриптам установки

Вспомогательные скрипты, которыми гоняли этот стенд (локально у оператора,
не обязательно в git):

```text
nta-bootstrap.sh           # Docker + CH + schema
nta-install-collectors.sh  # Go build + collectors (частично упал)
nta-finish-collectors.sh   # добивка systemd collectors
nta-install-worker.sh      # legacy: analytics + host rollups/geo
nta-fix-worker.sh         # staging DDL + --ignore-raw-lag + rerun
nta-install-ui.sh          # grapes-nta из tarball
# на следующих стендах сразу:
#   deploy/worker + deploy/enrichment (Docker), не host timers
#   BMP_LISTEN = порт роутеров + firewall allowlist
#   traffic talkers → ASN jobs (уже в worker crontab)
```

На сервере артефакты лежали в `/tmp/` и логировались через `tee` в том же
`tmux grapes`.

---

## 14. Краткая хронология

1. SSH survey → Docker  
2. ClickHouse compose + секьюрные пароли + apply schema (70)  
3. Collectors build/install → active `:6343` / BMP (сначала `:5000`, потом `:10179`)  
4. Analytics docker + rollup/geo timers (legacy этап)  
5. Fix staging + `--ignore-raw-lag` → geo/ASN загружены  
6. UI docker → `:3000`, admin seeded, health ok  
7. BMP peers online → `bgp-origin-refresh` → origin RIB → ASN в flows  
8. Talkers переведены на ASN-only; IP talker/pair сняты  
9. **2026-07-21:** cutover на `grapes-worker` + `grapes-enrichment`; host timers
   disabled; HTTP-shim вместо native clickhouse-client; enrichment scheduler на Python  

Итог: стенд принимает sFlow/BMP, отдаёт UI; периодические jobs и enrichment —
в Docker; collectors — на host systemd.
