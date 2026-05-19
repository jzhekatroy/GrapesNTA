# Runbook: постоянный `xdpflowd` под `systemd`

Универсальный сценарий перевода хоста с `ipt_NETFLOW` + `goflow2` на постоянный `xdpflowd` под `systemd`, с сохранением локального `nfcapd` и быстрым ручным откатом.

## Файлы

| Файл | Назначение |
|------|------------|
| [`deploy/systemd/xdpflowd.env.example`](../deploy/systemd/xdpflowd.env.example) | Универсальный шаблон `/etc/xdpflowd/xdpflowd.env` |
| [`deploy/systemd/xdpflowd-exec.sh`](../deploy/systemd/xdpflowd-exec.sh) | Обёртка systemd: читает env и запускает `xdpflowd` |
| [`deploy/systemd/xdpflowd.service`](../deploy/systemd/xdpflowd.service) | Универсальный unit-файл |
| [`scripts/prod_enable_xdpflowd.sh`](../scripts/prod_enable_xdpflowd.sh) | Включить постоянный режим |
| [`scripts/prod_rollback_legacy.sh`](../scripts/prod_rollback_legacy.sh) | Быстрый откат |

`sel`-совместимые команды сохранены как wrappers:

- [`scripts/prod_enable_xdpflowd_sel.sh`](../scripts/prod_enable_xdpflowd_sel.sh)
- [`scripts/prod_rollback_legacy_sel.sh`](../scripts/prod_rollback_legacy_sel.sh)
- [`deploy/sel/xdpflowd.env.example`](../deploy/sel/xdpflowd.env.example)

## Универсальное развёртывание

```bash
cd /opt/GrapesNTA  # или фактический checkout
make clean && make && make bpf

sudo mkdir -p /etc/xdpflowd
sudo cp deploy/systemd/xdpflowd.env.example /etc/xdpflowd/xdpflowd.env
sudo chmod 0600 /etc/xdpflowd/xdpflowd.env
sudoedit /etc/xdpflowd/xdpflowd.env
```

В env обязательно задать:

```bash
REPO_ROOT=/opt/GrapesNTA              # или фактический путь, например /root/GrapesNTA
IFACE=enp5s0d1                        # зеркальный интерфейс
XDP_CH_DSN=clickhouse://USER:PASS@HOST:9000/default
XDP_CH_TABLE=default.flows_raw
```

Опционально ограничить запуск конкретным хостом:

```bash
XDPFLOWD_EXPECT_HOST_SHORT=sel
```

## Текущий production default

Базовый профиль для постоянной работы, подтверждённый на `sel`:

```bash
XDP_MODE=generic
XDP_ACTION=drop
XDP_BPF_OBJ=${REPO_ROOT}/bpf/xdp_flow.o
NF_DSTS=127.0.0.1:9996

XDP_HEAVY_EXPORT=0
XDP_NF_ACTIVE=60s
XDP_NF_IDLE=10s
XDP_NF_TEMPLATE_INTERVAL=60s
XDP_NF_SCAN=1s

XDP_CH_SPOOL_MODE=required
XDP_CH_SPOOL_DIR=/var/lib/xdpflowd/ch-spool
XDP_CH_SPOOL_MAX_BYTES=214748364800
XDP_CH_SPOOL_FRAME_MAX_RECORDS=50000
XDP_CH_SPOOL_SHUTDOWN_DRAIN=300s
XDP_CH_WRITERS=8
XDP_TOP=0
XDP_JSON_OUT_ENABLE=0
```

На `sel` профиль показал `rx_fifo_errors=0/sec`, `softirq` ниже legacy и CPU заметно ниже, чем у варианта `XDP_HEAVY_EXPORT=1` с `500ms` scan.

## Включение

```bash
sudo ./scripts/prod_enable_xdpflowd.sh
```

Для host-specific путей можно переопределить:

```bash
sudo ENV_INSTALL=/etc/xdpflowd/sel.env \
  STATE_FILE=/root/xdpflowd_sel_permanent_state.env \
  ENV_TEMPLATE=$PWD/deploy/sel/xdpflowd.env.example \
  SERVICE_TEMPLATE=$PWD/deploy/sel/xdpflowd.service \
  EXEC_WRAPPER=$PWD/deploy/sel/xdpflowd-exec.sh \
  BACKUP_TAG=sel-permanent \
  ./scripts/prod_enable_xdpflowd.sh
```

Или для `sel` просто:

```bash
sudo ./scripts/prod_enable_xdpflowd_sel.sh
```

Скрипт сохраняет rollback state, снимает `ipt_NETFLOW`, останавливает `goflow2`, ставит systemd unit и проверяет, что сервис стал active. Если сервис не стартует, скрипт делает best-effort rollback.

## Проверки

```bash
systemctl status xdpflowd --no-pager
journalctl -u xdpflowd -f
```

Потери:

```bash
IF=enp5s0d1
a=$(cat /sys/class/net/$IF/statistics/rx_fifo_errors); sleep 60; b=$(cat /sys/class/net/$IF/statistics/rx_fifo_errors); echo "delta=$((b-a)) per_sec=$(( (b-a)/60 ))"
```

Локальный `nfcapd`:

```bash
nfdump -r /storage/nfdump/$(date +%Y-%m-%d)/<nfcapd.file> -o raw -c 5
```

ClickHouse:

```bash
clickhouse-client --host ... --query "SELECT count(), sum(packets), sum(bytes) FROM default.flows_raw WHERE time_received_ns > now64(9) - INTERVAL 5 MINUTE"
```

## Откат

```bash
sudo ./scripts/prod_rollback_legacy.sh
```

Для `sel`:

```bash
sudo ./scripts/prod_rollback_legacy_sel.sh
```

Откат останавливает `xdpflowd`, снимает XDP best-effort, возвращает `ipt_NETFLOW` правило из state и запускает `goflow2`. Spool не удаляется.

## Spool: устойчивость к повреждениям

Durable spool (`/var/lib/xdpflowd/ch-spool`) рассчитан на сценарий, когда ClickHouse временно недоступен или хост перезагрузился; данные приходят в `ClickHouse` после восстановления связи (at-least-once).

Авто-восстановление при повреждении одного фрейма:

- Drainer на любую ошибку чтения (`bad frame header`, `crc mismatch`, `excessive payload len`, `gob decode`) сканирует сегмент вперёд до следующего валидного `PFLX`-magic и продолжает с него. Лог содержит `spool corruption skipped` с `from`, `to`, `skipped_bytes`.
- Watchdog `XDP_CH_SPOOL_STALL_THRESHOLD` (default `60s`) форсирует тот же resync, если консумер ничего не двигал, хотя данные есть. Параметр также ограничивает ожидание `Close()` при остановке сервиса, чтобы `systemctl stop` не висел.
- Метрики в `journalctl -u xdpflowd`: `corruption_frames_skipped`, `corruption_bytes_skipped`, `lag_segments`, `drainer_progress_age`. Печатаются каждые `XDP_INTERVAL` (по умолчанию 5s).
- Печать `top-N` потоков (полный обход BPF flow-карты + сортировка) вынесена на отдельный таймер `XDP_TOP_INTERVAL` (по умолчанию `60s`). На короткий `XDP_INTERVAL` остаётся только дешёвый PERCPU-stats (без обхода карты). Если top-N вообще не нужен, поставьте `XDP_TOP_INTERVAL=0` или `XDP_TOP=0` — это ощутимо снижает CPU на высококардинальных хостах (десятки–сотни тысяч активных потоков).

Авто-восстановление checkpoint при старте:

- При запуске pipeline `meta/consumer.json` проходит две проверки. Если файл невалидный JSON (например, после ручной правки или прерванной записи), он автоматически переименовывается в `consumer.json.corrupt.<unix_ns>`, а pipeline стартует с дефолта (`seg=1 off=0`). В логах появляется `spool checkpoint corrupt; quarantined and reset to defaults`. Это закрывает старый crash-loop сценарий.
- Если checkpoint указывает за пределы реальных сегментов на диске (`cp.Segment > maxSeg+1`, например после очистки spool с сохранением `meta/`), либо отстаёт от ретеншна (`cp.Segment < minSeg`), checkpoint сбрасывается на самый старый существующий сегмент и сохраняется обратно. В логе строка `spool normalize: checkpoint ahead of writer; resetting to oldest segment` или `... behind retention; advancing to oldest segment` с `old`, `new`, `min_seg`, `max_seg`.
- Скрипт `scripts/prod_repair_spool.sh` остаётся для ручного контроля и старых бинарей, но рутинно его звать больше не надо — нормализация работает прозрачно при старте сервиса.

## Flow drainer: атомарное чтение BPF map

Раньше экспорт из BPF flow-карты делался в два шага: сначала `Iterate` (snapshot значений), затем `Delete` каждого ключа. Между этими шагами XDP-программа на других CPU продолжала инкрементить `packets`/`bytes` ровно этих же flow, и накопленная за интервал дельта **выбрасывалась** при `Delete`. Под нагрузкой ~3.5 Mpps это давало стабильную «недостачу» порядка 10–15% относительно `accounted_packets` из BPF stats — байты считались XDP, но в `flows_raw` так и не приезжали.

С версии после `41ed0c5` xdpflowd использует **атомарный** путь через `BPF_MAP_LOOKUP_AND_DELETE_ELEM` (`Map.LookupAndDelete`):

- Ядро возвращает значение counters на момент удаления entry в одном syscall. Гонка между «прочитал» и «удалил» исчезает.
- При старте делается probe на временной HASH-карте. Если ядро не поддерживает операцию (`< 5.14`), `xdpflowd` молча работает по старому пути и пишет `WARN` про потенциальный under-count.
- В `journalctl` каждые `XDP_INTERVAL` секунд печатается `flow drainer mode=atomic atomic_calls=N legacy_calls=M` — это и есть индикатор, что фикс активен.
- Если `LookupAndDelete` начнёт возвращать неожиданную ошибку в runtime, drainer однократно даунгрейдится в legacy на остаток lifetime процесса и пишет это в лог — никаких незаметных потерь данных.

Проверить, что путь активен после деплоя:

```bash
sudo journalctl -u xdpflowd -n 100 --no-pager | grep 'flow drainer'
# ожидаем: ... flow drainer mode=atomic atomic_calls=NN legacy_calls=0
```

Если после рестарта в логах строка `flow drainer ... mode=legacy` — значит ядро < 5.14 или probe не прошёл, и стоит обновить ядро для устранения under-count.

Если сервис всё-таки оказался застрявшим (например, бинарь старее версии с авто-resync), руками:

```bash
# Dry-run: скрипт сам остановит сервис, скажет какой будет новый чекпоинт.
sudo ./scripts/prod_repair_spool.sh

# Применить и поднять сервис.
sudo ./scripts/prod_repair_spool.sh --apply

# Кастомный путь к spool / имя сервиса:
sudo SPOOL_DIR=/var/lib/xdpflowd/ch-spool SERVICE=xdpflowd \
  ./scripts/prod_repair_spool.sh --apply
```

Скрипт делает резервные копии `consumer.json` и подозрительного сегмента (`*.suspect.<ts>`) — их можно потом отдать на forensics или удалить.
