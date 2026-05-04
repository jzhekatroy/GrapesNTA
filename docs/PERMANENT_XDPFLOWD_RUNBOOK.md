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
