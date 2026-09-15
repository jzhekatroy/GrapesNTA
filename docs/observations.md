# Наблюдения (Observations)

Единая фича: фильтры + виджеты. **Live** и **отчёт** — одна definition.

## Модель

| Поле | Назначение |
|---|---|
| `lookback` | окно графика live (`15m`…`7d`) |
| `live.refreshSec` | частота обновления экрана (≥300с) |
| `report.period` | `yesterday` \| `last_24h` |
| `report.schedule` | `{ kind, time, timezone, weekday?, day? }` |
| `report.emailTo` | получатели отчёта (до 10) |
| `materialize` | персональный rollup в `observation_rollups_5m` |
| `folder` / `description` / `isShared` / `layout` | организация доски |

Персональность = строки с `observation_id` в `observation_rollups_5m`, **не** отдельный MV на каждый id.

## Источники

| Scope | Live / Report |
|---|---|
| native Explorer (нет фильтров и groupBy, `dataSource: explorer`) | общий трафик через Explorer (`flows_raw`) |
| native dashboard (`dataSource: traffic_direction` \| `vlan_trend`) | `traffic_dashboard_1m` / `traffic_vlan_1m` через `trafficBandwidthSeries()` и `vlanDistributionTimeseries()` |
| иначе | только после materialize → `observation_rollups_5m` |

### Нативные шаблоны dashboard

Два отдельных наблюдения (пресеты в `observationPresets()`):

- **Входящий/исходящий трафик** — линии `in`/`out` из `traffic_dashboard_1m`
- **Трафик по VLAN** — Top-5 VLAN + «Прочие» из `traffic_vlan_1m`

Поле виджета `timeseries_bps.dataSource`: `explorer` (по умолчанию), `traffic_direction`, `vlan_trend`.

Для нативных шаблонов **materialize отключён** (персональный rollup не создаётся). Коллектор и список VLAN (для VLAN-шаблона) сохраняются в `widget.nativeScope` и используются и в live, и в отчётах. При создании из пресета сразу открываются настройки наблюдения. «Аплинк» — UI-название фильтра коллектора; один коллектор может суммировать несколько `source_id` с `include_in_total`.

Ось времени: direction-график использует время начала flow (`traffic_dashboard_1m`), VLAN — время приёма (`traffic_vlan_1m`).

UI не запускает rollup для Explorer-наблюдений — это делает контейнер `grapes-analytics` / `grapes-worker`.

## Analytics worker

| Сервис | Назначение |
|---|---|
| `grapes-nta` | UI + API (порт 3000) |
| `grapes-analytics` / analytics loop в worker | rollup + due reports |

Entrypoint: `server/analytics.js` — loop rollup (~60s) + проверка due reports (по умолчанию раз в 60с).

Переменные:

| Env | Default |
|---|---|
| `OBSERVATION_MAX_MATERIALIZE` | нет (0 = без лимита; положительное число включает потолок) |
| `OBSERVATION_ROLLUP_CONCURRENCY` | 1 |
| `OBSERVATION_ROLLUP_SHOT_MINUTES` | 15 |
| `OBSERVATION_ROLLUP_MAX_BEHIND_HOURS` | 24 |
| `OBSERVATION_BACKFILL_HOURS` | 24 |
| `OBSERVATION_ROLLUP_STUCK_SEC` | 900 |
| `ANALYTICS_REPORT_CHECK_SEC` | 60 |

При включении live курсор стартует с `createdAt` (догон настоящего). История за `OBSERVATION_BACKFILL_HOURS` добирается отдельной фазой с низким приоритетом.

## Отчёты

- Расписание: daily/weekly/monthly + локальное время в `schedule.timezone`.
- «Вчера» считается в таймзоне расписания (не UTC).
- Пропущенный слот старше 6 часов не догоняется.
- HTML + CSV пишутся на диск; при настроенном SMTP уходят на `emailTo`.
- История запусков: вкладка «Отчёты» на плитке.

SMTP: таблица `app_smtp_settings`, API `/api/settings/smtp` (только Administrator). UI — на вкладке диагностики наблюдений.

## Хранение

| Что | Где |
|---|---|
| Определения | ClickHouse `default.observations` |
| Runs | `default.observation_runs` (+ email_status/to/error) |
| HTML/CSV | `server/data/observation_runs/<id>/<runId>/` |
| SMTP | `default.app_smtp_settings` |

DDL: `deploy/clickhouse/observations_store.sql`, `deploy/clickhouse/app_smtp_settings.sql`.

## Квоты

- max активных materialize: **без лимита** (опционально `OBSERVATION_MAX_MATERIALIZE`)
- min refresh: **300s**
- concurrency воркера: **1**
- TTL rollup: **14 дней**
- детализация: **5 минут** (нормальная задержка данных ~10 минут)

## Виджеты

- `timeseries_bps` (+ опционально `dataSource` для dashboard-агрегатов)
- `top_table`

## API

- `GET/POST /api/observations`
- `GET/PUT/DELETE /api/observations/:id`
- `POST /api/observations/:id/preview`
- `POST /api/observations/:id/run`
- `POST /api/observations/:id/duplicate`
- `POST /api/observations/:id/cancel`
- `GET /api/observations/:id/runs`
- `GET /api/observations/:id/runs/:runId/artifact?file=report.html`
- `POST /api/observations/:id/materialize`
- `GET/PUT /api/settings/smtp`, `POST /api/settings/smtp/test`

## UI

`#observations` — доска (папки), настройки плитки, история отчётов, диагностика воркера + SMTP.
Из Explorer: «Как наблюдение».
