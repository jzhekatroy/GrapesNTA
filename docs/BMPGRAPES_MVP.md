# bmpgrapes - BMP collector MVP

`bmpgrapes` - минимальный BMP-приемник для GrapesNTA. Слушает TCP-порт, принимает
BMP-сессии от роутеров, разбирает peer up/down и route monitoring сообщения,
пишет нормализованные строки в ClickHouse.

Без Kafka, без OpenBMP DB. Один бинарь -> две таблицы ClickHouse:

```text
Router --BMP TCP--> bmpgrapes --INSERT--> ClickHouse bmp_*
                                             |
                                             v
                                       Laravel API
                                             |
                                             v
                                       MoonShine dashboards
```

## Scope MVP

Парсинг:

- BMP common header (RFC 7854).
- BMP per-peer header.
- Peer Up Notification, Peer Down Notification.
- Route Monitoring (один BGP UPDATE на сообщение).
- BGP UPDATE: withdrawn/announced IPv4, MP_REACH/MP_UNREACH для IPv6 unicast.
- Path attributes: ORIGIN, AS_PATH (4-byte ASN), NEXT_HOP, MED, LOCAL_PREF.

Не входит в MVP (можно добавить позже):

- VPNv4/VPNv6, BGP-LS, EVPN, FlowSpec.
- 2-byte ASN AS_PATH (legacy peers).
- Хранение текущего RIB (`bmp_routes_current`) - сейчас только append-only event log.
- Парсинг Statistics Report.
- BMP TLS.

## ClickHouse таблицы

DDL: [`deploy/clickhouse/bmp.sql`](../deploy/clickhouse/bmp.sql).

- `default.bmp_peers` - события peer up / peer down.
- `default.bmp_route_events` - append-only лог announce/withdraw (источник правды).
- `default.bgp_updates_1m` - SummingMergeTree, минутная агрегация updates/withdrawals по роутеру и пиру. **Не имеет Materialized View** — наполняется периодическим `INSERT … SELECT` (или дашборд читает напрямую из `bmp_route_events`).

> Почему без MV. Первичный RIB-dump от роутера — это десятки/сотни тысяч NLRI за несколько секунд. Если на горячий путь повесить MV `bgp_updates_1m_mv`, ClickHouse начинает падать в `memory limit exceeded` на стороне MV, а `bmpgrapes` из-за этого теряет строки. DDL и пример периодической агрегации — в [`deploy/clickhouse/bmp.sql`](../deploy/clickhouse/bmp.sql).
>
> Если на старой инсталляции MV уже создан, удалите его:
>
> ```sql
> DROP TABLE IF EXISTS default.bgp_updates_1m_mv;
> ```

Применить:

```bash
clickhouse-client \
  --host 127.0.0.1 --port 9000 \
  --user develop --password 'PASSWORD' \
  --multiquery < deploy/clickhouse/bmp.sql
```

## Сборка

```bash
make build-bmp
# binary: ./bin/bmpgrapes
```

## Запуск

```bash
sudo ./bin/bmpgrapes \
  -listen 0.0.0.0:5000 \
  -ch-dsn 'clickhouse://develop:PASSWORD@127.0.0.1:9000/default' \
  -ch-events-table default.bmp_route_events \
  -ch-peers-table default.bmp_peers
```

Ключевые флаги:

| Flag | Default | Описание |
|------|---------|----------|
| `-listen` | `0.0.0.0:5000` | TCP-порт для входящих BMP-сессий |
| `-ch-dsn` | - | ClickHouse DSN, обязательный |
| `-ch-events-table` | `default.bmp_route_events` | таблица событий маршрутов |
| `-ch-peers-table` | `default.bmp_peers` | таблица peer-событий |
| `-ch-batch-size` | `1000` | размер пакетной вставки |
| `-ch-flush-interval` | `1s` | периодический flush |
| `-ch-queue-size` | `4096` | глубина внутренней очереди до ClickHouse |
| `-ch-queue-mode` | `block` | поведение при переполнении: `block` (по умолчанию, TCP back-pressure роутеру, без потерь) или `drop` (legacy, дропает пакеты) |
| `-allow-routers` | пусто | optional whitelist IP роутеров |
| `-max-message-bytes` | `65535` | потолок BMP-сообщения |
| `-interval` | `10s` | период логирования метрик |
| `-log-level` | `info` | `debug` / `info` / `warn` / `error` |
| `-log-format` | `text` | `text` (человекочитаемо) или `json` (для парсера логов) |
| `-log-update-samples` | `10` | сколько первых BGP UPDATE на сессию логировать на Info |

## Логирование и отладка

`-log-level` управляет тем, сколько подробностей попадает в лог:

- `info` — стандартный режим: сессии, peer up/down, первые N BGP UPDATE-сэмплов на сессию, периодические метрики сервера и ClickHouse, аварии при разборе.
- `debug` — то же плюс лог на каждое принятое BMP-сообщение (`type`, `length`) и тип сообщений `initiation` / `statistics_report` / `route_mirroring`.
- `warn` — только проблемы.

`-log-format json` удобен для `journalctl -o cat | jq`, ELK или Loki.

Что видно в `info`-логе по умолчанию:

```text
bmpgrapes session opened           router=10.0.0.1
bmpgrapes peer up                  router=10.0.0.1 peer=192.0.2.1 peer_asn=65000 is_ipv6=false ...
bmpgrapes bgp update sample        router=10.0.0.1 peer=192.0.2.1 event=announce family=4 prefix=8.8.8.0/24 next_hop=192.0.2.1 origin_asn=15169 ...
bmpgrapes clickhouse               events_queued=... events_written=... insert_errs=0 queue_drops=0
bmpgrapes server                   sessions_open=1 sessions_accepted=1 messages_parsed=1234 bgp_parse_errs=0
bmpgrapes peer down                router=10.0.0.1 peer=192.0.2.1 peer_asn=65000 reason=remote_system_close_notification
bmpgrapes session ended            router=10.0.0.1 messages=1234 route_monitoring=1100 announces=900 withdraws=10 parse_errs=0
```

При ошибке разбора BMP/BGP сервис залогирует `Warn` с коротким `body_hex_head` /
`bgp_hex_head` (первые 64 байта) — это нужно отдавать в отладку, чтобы было видно, какой
байт-в-байт пакет упал. Полный пакет в лог не пишется.

Просмотр логов на проде:

```bash
journalctl -u bmpgrapes -f --since "5 minutes ago"
journalctl -u bmpgrapes -n 200 -o cat
```

Если включить `BMP_LOG_FORMAT=json`:

```bash
journalctl -u bmpgrapes -n 200 -o cat | jq 'select(.msg | startswith("bmpgrapes bgp update"))'
```

## systemd

Файлы:

- `deploy/systemd/bmpgrapes.service`
- `deploy/systemd/bmpgrapes-exec.sh`
- `deploy/systemd/bmpgrapes.env.example`

Установка:

```bash
sudo mkdir -p /etc/bmpgrapes /opt/GrapesNTA/bin
sudo cp deploy/systemd/bmpgrapes.env.example /etc/bmpgrapes/bmpgrapes.env
sudo chmod 0600 /etc/bmpgrapes/bmpgrapes.env
sudo install -m 0755 deploy/systemd/bmpgrapes-exec.sh /opt/GrapesNTA/deploy/systemd/bmpgrapes-exec.sh
sudo install -m 0644 deploy/systemd/bmpgrapes.service /etc/systemd/system/bmpgrapes.service
sudo systemctl daemon-reload
sudo systemctl enable --now bmpgrapes
```

## Настройка роутера

Cisco IOS-XR пример (синтаксис вендора уточнять отдельно):

```text
bmp server 1
 host 10.0.0.10 port 5000
 description grapesnta-bmp
 update-source Loopback0
!
router bgp 65000
 neighbor 192.0.2.1 bmp-activate server 1
```

Juniper Junos пример:

```text
set routing-options bmp station grapesnta connection-mode active
set routing-options bmp station grapesnta station-address 10.0.0.10
set routing-options bmp station grapesnta station-port 5000
set routing-options bmp station grapesnta route-monitoring pre-policy
```

## Проверка работы

После запуска и подключения роутера:

```sql
SELECT state, count() FROM default.bmp_peers WHERE ts >= now() - INTERVAL 10 MINUTE GROUP BY state;
SELECT event_type, count() FROM default.bmp_route_events WHERE ts >= now() - INTERVAL 10 MINUTE GROUP BY event_type;

-- Минутный график без MV: читаем напрямую из bmp_route_events
SELECT
    toStartOfMinute(ts) AS minute,
    countIf(event_type = 'announce') AS announces,
    countIf(event_type = 'withdraw') AS withdraws
FROM default.bmp_route_events
WHERE ts >= now() - INTERVAL 30 MINUTE
GROUP BY minute
ORDER BY minute DESC;

-- bgp_updates_1m остается пустым до тех пор, пока не запущен периодический
-- INSERT … SELECT (см. пример в deploy/clickhouse/bmp.sql).
```

## Backpressure и очередь к ClickHouse

`bmpgrapes` принимает BMP-сообщения по TCP и складывает их в ограниченную очередь,
из которой воркер делает батч-INSERT в ClickHouse. При временной деградации ClickHouse
(GC паузы, тяжелые мердж/MV в соседних таблицах, нехватка памяти и т.п.) очередь начинает
заполняться. Поведение при заполнении определяется флагом `-ch-queue-mode`:

- `block` (значение по умолчанию). Когда очередь полна, `EnqueueEvents` / `EnqueuePeers`
  блокируется до появления места. Чтение из BMP TCP-сокета также приостанавливается,
  TCP-receive буфер заполняется, и роутер автоматически замедляет отправку. Так
  данные не теряются: либо они уйдут в ClickHouse, либо роутер сам поставит сессию
  на паузу. В логах при этом периодически появляется:

  ```text
  WARN bmpgrapes clickhouse queue saturated (applying back-pressure)
       blocked_rows_last_window=... queue_blocks_total=...
  ```

  Это нормально на старте, во время первичного RIB-dump.

- `drop` (legacy). Когда очередь полна, батч отбрасывается, в `queue_drops_total`
  растет счетчик, в логах появляется:

  ```text
  WARN bmpgrapes clickhouse queue full (drop mode)
       dropped_rows_last_second=... queue_drops_total=...
  ```

  Использовать только если вам важнее, чтобы BMP-сессия с роутером не приостанавливалась,
  и при этом терпимо терять часть записей о маршрутах.

Размер очереди (`-ch-queue-size`) и размер батча (`-ch-batch-size`) можно поднять,
если ClickHouse в норме обрабатывает поток, но не успевает за пиками. Для типового
RIB-dump 1–2 миллиона префиксов: `-ch-queue-size 16384`, `-ch-batch-size 4000` работает.

## Метрики

Сервис каждые `-interval` пишет в лог сводку:

```text
sessions_open
sessions_accepted
sessions_closed
messages_parsed
messages_rejected
bgp_parse_errs
events_queued / events_written
peers_queued / peers_written
insert_errs
queue_drops    # копится только в режиме -ch-queue-mode=drop
queue_blocks   # копится только в режиме -ch-queue-mode=block (метрика back-pressure)
queue_mode     # текущий режим очереди
```

## Безопасность

BMP по TCP без TLS. На внешнем периметре обязателен firewall:

- разрешать только IP роутеров;
- или дополнительно ограничивать через `-allow-routers`.

## Roadmap (после MVP)

- `bmp_routes_current` - текущая RIB, синхронизация по peer up/down/withdraw.
- `bmp_prefix_origin_current` - lookup префикс -> origin ASN для enrichment flows.
- Materialized views для top ASN/prefix.
- Поддержка 2-byte ASN и VPNv4/VPNv6.
- BMP over TLS (RFC 9069).
