# Установка первого стенда GrapesNTA + UI (сервер `nta`)

Дата: **2026-07-20**  
Хост: **nta** · `5.188.236.212`  
ОС: Debian (Docker CE)  
Git: GrapesNTA `main` → `/opt/GrapesNTA`  
Наблюдение за установкой: `tmux attach -t grapes`

Документ фиксирует **фактический** этап установки на этом сервере (что сделали,
куда положили, какие пароли, какие грабли и фиксы). Для повтора на новом хосте —
использовать как чеклист; секреты на следующем стенде генерировать заново.

---

## 1. Целевая архитектура (согласовано)

| Слой | Что | Как |
|------|-----|-----|
| Host / systemd | `flowcollectord`, `bmpgrapes` | бинарники из GrapesNTA |
| Host / systemd timers | traffic rollups, talkers rollups, `geoloaderd` | Python-скрипты из GrapesNTA |
| Docker | ClickHouse | `grapes-clickhouse` |
| Docker | observations analytics worker | `grapes-analytics` (host network) |
| Docker | UI NTAdmin | `grapes-nta` (host network, порт **3000**) |

Схема ClickHouse — **универсальная** (flows / DNS / BMP / traffic / observations / RBAC).
Профиль площадки выбирает демоны, не форму БД.

XDP/`dnsflowd` на этом стенде **не ставили** (опционально по площадке).

Firewall: `INPUT` policy **DROP**, SSH только из ipset `ssh`
(`/etc/iptables/rules.v4`, `netfilter-persistent`).  
UI `:3000` открыт **тем же ipset** `ssh` (2026-07-20).  
sFlow `:6343/udp` и BMP `:5000/tcp` — **ACCEPT** (иначе трафик не доходит; 2026-07-20).  
CH `:8123`/`:9000` снаружи по-прежнему закрыты.

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
     - BMP listen `0.0.0.0:5000`
     - events → `bmp_route_events`, peers → `bmp_peers`

4. `systemctl enable --now flowcollectord bmpgrapes`.

### Грабли этапа B

Скрипт установки с `set -e` упал на noop/`cp` вокруг `bmpgrapes-exec.sh`
**до** enable unit’ов. Бинарники уже были собраны — добивали отдельным
finish-скриптом (копирование unit’ов, env, `daemon-reload`, start).

Проверка:

```bash
systemctl is-active flowcollectord bmpgrapes
ss -ulnp | grep 6343
ss -tlnp | grep 5000
```

---

## 7. Этап C — worker (analytics + rollups + geo)

### C1. Observations analytics (Docker)

`/opt/grapes/worker/docker-compose.yml` — образ из
`/opt/GrapesNTA/deploy/analytics`, `network_mode: host`, data → `./data`.

`.env` указывает на локальный CH (`ui_admin` / `ui_read`), маппинг колонок
`flows_raw` (`time_received_ns`, `src_addr`, …).

```bash
cd /opt/grapes/worker && docker compose up -d --build
docker logs -f grapes-analytics
```

### C2. Wrapper `clickhouse-client`

```bash
# /usr/local/bin/clickhouse-client → docker exec -i grapes-clickhouse clickhouse-client "$@"
```

Нужен host-скриптам rollup/geo, которые вызывают CLI, а не HTTP.

### C3. Traffic rollups + talkers (systemd timers)

- env: `/etc/grapesnta/traffic-rollups.env`, `traffic-talkers-rollups.env`
- units из `deploy/systemd/traffic-*.{service,timer}`
- `systemctl enable --now traffic-rollups.timer traffic-talkers-rollups.timer`

### C4. RIR geo / ASN (`geoloaderd`)

- env: `/etc/geoloaderd/geoloaderd.env`
- cache: `/var/lib/geoloaderd/cache`
- `systemctl enable --now geoloaderd.timer`
- первый прогон: `systemctl start geoloaderd.service` (минуты, качает RIPE/APNIC/…)

---

## 8. Этап D — фиксы свежего стенда (worker)

После первого прогона:

| Проблема | Симптом | Фикс |
|----------|---------|------|
| Нет `asn_registry_staging` | `geoloaderd` падает после download RIR | в git: `deploy/schema/40_enrichment/08_asn_registry_staging.sql` |
| Нет `asn_registry_enriched` | `traffic_country_1m` rollup error | в git: `deploy/schema/40_enrichment/09_asn_registry_enriched.sql` |
| Нет `traffic_talker_*` / `traffic_pair_*` | talkers timer error UNKNOWN_TABLE | в git: `deploy/schema/60_traffic/17–20_*.sql` |
| Пустой `flows_raw` | rollups skip / exit 1 из‑за raw lag | в unit добавить `--ignore-raw-lag` к `traffic_rollup_async.py`; для свежего стенда допустимо поднять `TRAFFIC_ROLLUP_MAX_RAW_LAG_SECONDS` |
| Rollups state отстаёт от raw | `traffic_dashboard_1m = 0`, state на старых датах | `traffic_rollup_async.py`: empty bootstrap от `now()-safety_lag`, skip-forward к min(raw); разово: `scripts/nta-unblock-rollups.sh` |
| Geo без ASN | `geo_prefix_country` > 0, `asn_registry` = 0 | после staging — повторный `systemctl start geoloaderd` |

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
| ASN = 0 | нет BMP peers + нет `ip_asn_prefixes` + нет `origin_asn` в L3 | BMP на `:5000` и/или loader IP→ASN; свои сети — через L3 |
| В UI «нет VLAN», а в raw VLAN есть | раньше `traffic_vlan_1m` и VLAN API **исключали** `direction=unknown` | фикс в `traffic_rollup_jobs.py` + `VLAN_FLOW_DIRECTIONS` (включает `unknown`) |
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
2. **Дыры схемы** — `asn_registry_enriched`, `traffic_talker_*`, `traffic_pair_*`
   должны быть в `deploy/schema` (см. MANIFEST 08–09, 17–20).
3. **Bootstrap rollups** — при пустом raw старый код стартовал с `now()-7d` и
   молотил пустые минуты; новый `traffic_rollup_async.py` стартует от
   `now()-safety_lag` и делает skip-forward к `min(flows_raw)` для enabled sources.

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
| 5000/tcp | BMP → bmpgrapes |

---

## 11. Быстрая проверка после установки

```bash
tmux attach -t grapes   # опционально

docker ps --format 'table {{.Names}}\t{{.Status}}'
# grapes-clickhouse, grapes-analytics, grapes-nta

systemctl is-active flowcollectord bmpgrapes
systemctl is-active traffic-rollups.timer traffic-talkers-rollups.timer geoloaderd.timer

clickhouse-client -q "SELECT count() FROM system.tables WHERE database='default'"
clickhouse-client -q "SELECT count() FROM geo_prefix_country"
clickhouse-client -q "SELECT count() FROM asn_registry"
clickhouse-client -q "SELECT count() FROM flows_raw"

curl -sS http://127.0.0.1:3000/api/health | head -c 200; echo
```

Ожидание до подачи трафика: `flows_raw = 0`. После направления sFlow на
`:6343` — рост `flows_raw`, затем заполнение traffic rollups.

---

## 12. Известные долги / следующие шаги

- [x] Добавить `asn_registry_staging` + `asn_registry_enriched` + talker/pair в `deploy/schema`
- [x] Rollups: empty bootstrap + skip-forward в `traffic_rollup_async.py`
- [x] UI `:3000` — ACCEPT из ipset `ssh` (persist в `/etc/iptables/rules.v4`)
- [ ] CH `:8123`/`:9000` снаружи не открывать (сейчас DROP)
- [ ] Сменить пароль UI `admin`
- [ ] Опционально: loaders `ip_asn_prefixes` / `asn_names`
- [ ] Опционально: единый образ `grapes-worker` вместо analytics docker + host timers
- [ ] Подать реальный sFlow/BMP на стенд
- [ ] При необходимости: SNMP / XDP / dnsflowd по профилю площадки

---

## 13. Соответствие локальным скриптам установки

Вспомогательные скрипты, которыми гоняли этот стенд (локально у оператора,
не обязательно в git):

```text
nta-bootstrap.sh           # Docker + CH + schema
nta-install-collectors.sh  # Go build + collectors (частично упал)
nta-finish-collectors.sh   # добивка systemd collectors
nta-install-worker.sh      # analytics + rollups + geoloaderd
nta-fix-worker.sh         # staging DDL + --ignore-raw-lag + rerun
nta-install-ui.sh          # grapes-nta из tarball
```

На сервере артефакты лежали в `/tmp/` и логировались через `tee` в том же
`tmux grapes`.

---

## 14. Краткая хронология

1. SSH survey → Docker  
2. ClickHouse compose + секьюрные пароли + apply schema (70)  
3. Collectors build/install → active `:6343` / `:5000`  
4. Analytics docker + rollup/geo timers  
5. Fix staging + `--ignore-raw-lag` → geo/ASN загружены  
6. UI docker → `:3000`, admin seeded, health ok  

Итог: стенд готов принимать sFlow/BMP и отдавать UI; аналитика справочников
(geo/ASN) заполнена; сырой трафик появится после источника.
