# Runbook: старт нового коллектора GrapesNTA

Документ описывает порядок подготовки нового сервера-коллектора перед подачей
зеркального трафика. Цель: проверить железо/NIC, подготовить `xdpflowd` и
`dnsflowd`, а затем безопасно протестировать XDP.

Текущий новый сервер:

```text
host: m61
OS: Debian 13 (trixie)
kernel: 6.12.90+deb13.1-amd64
management NIC: enp1s0f0np0, IP 95.215.0.15/27
mirror NIC: ens1np0
mirror NIC driver: mlx5_core
mirror NIC card: Mellanox ConnectX-4
mirror NIC firmware: 12.28.2006 (MT_2180110032)
```

Важно: management-интерфейс не трогаем для XDP. Все тесты XDP/захвата делаем
только на mirror-интерфейсе.

`m61` готовится как **замена** текущего сервера `netflow`. Пока оба сервера могут
работать параллельно, нельзя писать в ClickHouse с одинаковыми `source_id`, иначе
дашборд будет двойно считать один и тот же трафик.

Рекомендуемый порядок source_id:

| Этап | `xdpflowd` source_id | `dnsflowd` source_id | Назначение |
|------|----------------------|----------------------|------------|
| Тест до cutover | `xdp-m61` | `dns-m61` | Проверить новый сервер без смешивания со старым |
| Финальный cutover | `netflow` | `dns-netflow` | Полная замена старого сервера с сохранением истории UI |

Для тестовых source_id держать `include_in_total = 0`, пока старый `netflow`
продолжает писать production traffic. На финальном переключении старый сервер
останавливается, и `m61` начинает писать в старые production source_id.

---

## 1. Найти правильный mirror-интерфейс

Сначала вывести все сетевые интерфейсы:

```bash
ip -br link
ip a
```

На `m61` сейчас:

```text
enp1s0f0np0  UP, 95.215.0.15/27  -> management
ens1np0      DOWN                 -> mirror / XDP candidate
```

Проверить все NIC:

```bash
for IF in enp1s0f0np0 enp1s0f1np1 ens1np0 enp1s0f2np2 enp1s0f3np3; do
  echo
  echo "================ $IF ================"
  ip -br link show "$IF"
  echo "-- driver"
  ethtool -i "$IF" 2>/dev/null || true
  echo "-- link"
  ethtool "$IF" 2>/dev/null | egrep 'Speed|Duplex|Auto-negotiation|Link detected|Port|Supported link modes' || true
  echo "-- pci"
  readlink -f /sys/class/net/$IF/device 2>/dev/null || true
done

echo
echo "== PCI network devices =="
lspci -nn | egrep -i 'ethernet|network|mellanox|intel|broadcom'
```

На `m61` mirror-кандидат:

```text
ens1np0
driver: mlx5_core
bus-info: 0000:81:00.0
PCI: Mellanox Technologies MT27700 Family [ConnectX-4] [15b3:1013]
```

---

## 2. Проверить PCIe-шину, NUMA и локальные CPU

Это важный пункт. На старом сервере мы отдельно проверяли PCIe link, потому что
карта могла быть capable `8GT/s x8`, но фактически работать ниже. Для нового
сервера нужно всегда фиксировать `LnkCap` и `LnkSta`.

```bash
IF=ens1np0
PCI=$(basename "$(readlink -f /sys/class/net/$IF/device)")
echo "IF=$IF PCI=$PCI"

echo
echo "== lspci short =="
lspci -s "$PCI" -nn

echo
echo "== PCIe link capability/status =="
lspci -s "$PCI" -vv | egrep -i 'LnkCap:|LnkSta:|Width|Speed'

echo
echo "== NUMA node =="
cat /sys/class/net/$IF/device/numa_node

echo
echo "== local CPUs =="
cat /sys/class/net/$IF/device/local_cpulist

echo
echo "== IRQs for interface =="
grep "$IF" /proc/interrupts || true
```

Текущий результат `m61` хороший:

```text
IF=ens1np0 PCI=0000:81:00.0
LnkCap: Speed 8GT/s, Width x16
LnkSta: Speed 8GT/s, Width x16
NUMA node: 1
local CPUs: 14-27,42-55
```

Вывод: PCIe-шина не выглядит узким местом. ConnectX-4 на `mlx5_core` лучше
подходит для native XDP, чем старая `mlx4_en`.

---

## 3. Зафиксировать baseline NIC до трафика

Пока зеркало не подключено, не нужно агрессивно тюнить ring/coalescing. Достаточно
поднять интерфейс и включить promiscuous mode.

```bash
IF=ens1np0
ip link set "$IF" up
ip link set "$IF" promisc on
```

Сохранить baseline:

```bash
ethtool -i "$IF"
ethtool "$IF" | egrep 'Speed|Duplex|Auto-negotiation|Link detected|Port'
ethtool -g "$IF"
ethtool -c "$IF"
ethtool -l "$IF"
ethtool -a "$IF"
ip -details link show dev "$IF" | sed -n '1,25p'
```

Текущий baseline `m61/ens1np0`:

```text
state: NO-CARRIER, PROMISC, UP
link: no cable / no traffic yet
driver: mlx5_core
RX ring current/max: 1024 / 8192
TX ring current/max: 1024 / 8192
channels combined: 56 / 56
adaptive-rx: on
rx-usecs: 8
rx-frames: 128
pause RX/TX: on/on
```

### VLAN на mirror-порту

SPAN отдаёт tagged кадры (`802.1Q`), но при `rx-vlan-offload: on` mlx5 снимает
тег **до XDP** — в `flows_raw.src_vlan` будет `0`, хотя `tcpdump` видит VLAN.

Проверка:

```bash
IF=ens1np0
sudo timeout 5 tcpdump -i $IF -nn -e -c 10 'vlan'
ethtool -k $IF | grep -i vlan
```

Исправление (делает `deploy/systemd/xdpflowd-exec.sh` при `XDP_MIRROR_RXVLAN_OFF=1`):

```bash
sudo ethtool -K $IF rxvlan off txvlan off
sudo ethtool -K $IF rx-vlan-filter off
sudo systemctl restart xdpflowd
```

Проверка после фикса:

```bash
journalctl -u xdpflowd -n 30 | grep vlan_tag_seen
$CH --query "
SELECT src_vlan, count() c, round(sum(bytes)/1e9, 2) gb
FROM flows_raw
WHERE source_id='netflow'
  AND time_received_ns >= now64(9) - INTERVAL 2 MINUTE
  AND src_vlan != 0
GROUP BY src_vlan ORDER BY gb DESC LIMIT 10
FORMAT PrettyCompact"
```

Для подписей VLAN в UI заполнить `net_l2_vlans` (vlan 210 → customer, 444 → uplink и т.д.).

Не менять `rx 8192`, coalescing и pause до подачи трафика, если нет проблемы.
На старом `sel` такой tuning понадобился из-за `rx_fifo_errors`, но это была
другая карта/драйвер (`mlx4_en`) и другой профиль.

---

## 4. Проверить счётчики без трафика

```bash
IF=ens1np0

A_RX=$(cat /sys/class/net/$IF/statistics/rx_packets)
A_BYTES=$(cat /sys/class/net/$IF/statistics/rx_bytes)
A_DROP=$(cat /sys/class/net/$IF/statistics/rx_dropped)
A_FIFO=$(cat /sys/class/net/$IF/statistics/rx_fifo_errors)
sleep 10
B_RX=$(cat /sys/class/net/$IF/statistics/rx_packets)
B_BYTES=$(cat /sys/class/net/$IF/statistics/rx_bytes)
B_DROP=$(cat /sys/class/net/$IF/statistics/rx_dropped)
B_FIFO=$(cat /sys/class/net/$IF/statistics/rx_fifo_errors)

echo "rx_pps=$(( (B_RX-A_RX)/10 ))"
echo "rx_gbps=$(awk "BEGIN { printf \"%.3f\", (($B_BYTES-$A_BYTES)*8/10)/1000000000 }")"
echo "rx_dropped_delta=$((B_DROP-A_DROP))"
echo "rx_fifo_delta=$((B_FIFO-A_FIFO))"
```

До подключения зеркала ожидаемо:

```text
rx_pps=0
rx_gbps=0.000
rx_dropped_delta=0
rx_fifo_delta=0
```

---

## 5. Подготовить GrapesNTA на сервере

Важно: `dnsflowd`, `flowcollectord`, DNS rollups и последние systemd-шаблоны
пока находятся в ветке `feature/dnsflowd-mvp`. Если клонировать `main`, там
может не быть `cmd/dnsflowd`, и команда сборки DNS завершится ошибкой:

```text
stat /opt/GrapesNTA/cmd/dnsflowd: directory not found
```

Пакеты для сборки на Debian 13:

```bash
apt update
apt install -y \
  git \
  make \
  gcc \
  clang \
  llvm \
  pkg-config \
  libbpf-dev \
  libpcap-dev \
  linux-libc-dev \
  linux-headers-$(uname -r) \
  golang \
  ethtool \
  iproute2 \
  tcpdump \
  lsof
```

`libpcap-dev` нужен именно для `dnsflowd` (`github.com/google/gopacket/pcap`).
Если его нет, сборка падает так:

```text
fatal error: pcap.h: No such file or directory
```

Первичная установка:

```bash
cd /opt
git clone https://github.com/jzhekatroy/GrapesNTA.git
cd /opt/GrapesNTA

git fetch origin
git checkout feature/dnsflowd-mvp
git pull

make clean
make          # builds bpf/xdp_flow.o + bin/xdpflowd
make build-dns
```

Если репозиторий уже есть:

```bash
cd /opt/GrapesNTA

git fetch origin
git checkout feature/dnsflowd-mvp
git pull

make clean
make
make build-dns
```

Проверить бинарники и BPF:

```bash
ls -lh bin/xdpflowd bin/dnsflowd bpf/xdp_flow.o
```

Если на свежем сервере сборка падает с `missing go.sum entry`, выполнить один
раз:

```bash
go mod tidy
make clean
make
make build-dns
```

`go mod tidy` может изменить локальный `go.sum`; это нормально для сборки на
сервере. Позже нужно закоммитить актуальный `go.sum` в репозиторий, чтобы новые
серверы собирались без ручного tidy.

Для уже начатой установки на `m61`, где был случайно собран `main`, команда
исправления:

```bash
cd /opt/GrapesNTA

git fetch origin
git checkout feature/dnsflowd-mvp
git pull

go mod tidy
make clean
make
make build-dns

ls -lh bin/xdpflowd bin/dnsflowd bpf/xdp_flow.o
```

---

## 6. Подготовить ClickHouse-схему

На любом хосте с доступом к ClickHouse:

```bash
CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='***' \
  ./deploy/clickhouse/apply_catalog_tables.sh

CH_HOST=95.215.1.30 CH_PORT=6124 CH_USER=develop CH_PASSWORD='***' \
  ./deploy/clickhouse/apply_dns_tables.sh
```

Проверить, что нужные таблицы есть:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '***' --query "
SELECT name, engine
FROM system.tables
WHERE database = 'default'
  AND name IN (
    'flows_raw',
    'dns_log',
    'dns_answers',
    'net_locations',
    'net_collectors',
    'net_flow_sources')
ORDER BY name
FORMAT PrettyCompact
"
```

---

## 7. Зарегистрировать source_id для нового сервера

Для теста нового сервера не переиспользовать старые `source_id`. Рекомендуемые
тестовые имена:

```text
xdp-m61
dns-m61
```

Пример регистрации:

```sql
INSERT INTO default.net_flow_sources
    (source_id, display_name, source_type, collector_id, location,
     description, include_in_total, enabled, updated_at)
VALUES
    ('xdp-m61', 'm61 XDP mirror', 'xdp', '', '',
     'm61 ens1np0 XDP collector test source', 0, 1, now());

INSERT INTO default.net_flow_sources
    (source_id, display_name, source_type, collector_id, location,
     description, include_in_total, enabled, updated_at)
VALUES
    ('dns-m61', 'm61 DNS mirror', 'dns', '', '',
     'm61 ens1np0 DNS collector', 0, 1, now());
```

На тестовом этапе и `xdp-m61`, и `dns-m61` должны быть `include_in_total = 0`,
чтобы не сломать production dashboard, пока старый `netflow` ещё пишет данные.
После финального cutover можно либо:

- переключить env `m61` на старые `source_id` (`netflow`, `dns-netflow`);
- либо оставить новые `source_id`, но тогда отдельно включить `xdp-m61` в total и
  принять разрыв истории по source_id.

Для замены старого сервера предпочтительнее первый вариант: финально использовать
`XDPFLOWD_SOURCE_ID=netflow` и `DNSFLOWD_SOURCE_ID=dns-netflow`.

Когда появятся записи в `net_locations` и `net_collectors`, привязать источники
через `collector_id`.

---

## 8. Подготовить `xdpflowd`

```bash
cd /opt/GrapesNTA

sudo mkdir -p /etc/xdpflowd
sudo cp deploy/systemd/xdpflowd.env.example /etc/xdpflowd/xdpflowd.env
sudo chmod 0600 /etc/xdpflowd/xdpflowd.env
sudoedit /etc/xdpflowd/xdpflowd.env
```

Минимально выставить:

```bash
REPO_ROOT=/opt/GrapesNTA
IFACE=ens1np0
XDP_BPF_OBJ=${REPO_ROOT}/bpf/xdp_flow.o

# На старой mlx4_en native был проблемным. На mlx5_core native подтверждён рабочим
# и более выгодным (см. раздел 16): меньше softirq, нет потерь на железе.
# Для первого smoke test можно стартовать на generic, затем переключить на native.
# Текущий боевой режим m61: native.
XDP_MODE=native
XDP_ACTION=drop

# Если dnsflowd будет слушать тот же mirror-интерфейс, DNS надо пропускать.
XDP_DNS_PASSTHROUGH=1

XDPFLOWD_SOURCE_ID=xdp-m61
XDP_CH_DSN=clickhouse://develop:***@95.215.1.30:6124/default
XDP_CH_TABLE=default.flows_raw
XDP_CH_SAMPLER_ADDR=95.215.0.15

# Обязательно для direction/src_role/dst_role/network_name.
# Если оставить 0, flows_raw будет писаться, но классификация на графиках
# станет unknown/пустой.
XDP_CLASSIFIER=1
XDP_CLASSIFIER_REFRESH=60s
XDP_CLASSIFIER_BGP_TABLE=default.bgp_prefix_origin_current
XDP_CLASSIFIER_L3_PREFIXES_VIEW=default.net_l3_prefixes_enabled
XDP_CLASSIFIER_L2_VLANS_VIEW=default.net_l2_vlans_enabled

XDP_CH_SPOOL_MODE=required
XDP_CH_SPOOL_DIR=/var/lib/xdpflowd/ch-spool
XDP_CH_SPOOL_MAX_BYTES=214748364800
XDP_CH_SPOOL_FRAME_MAX_RECORDS=50000
# Keep `systemctl stop` fast; spool is durable and replays leftover backlog on
# next start. Use 300s only for planned A/B swaps that must flush before stop.
XDP_CH_SPOOL_SHUTDOWN_DRAIN=30s
XDP_CH_WRITERS=8

XDP_TOP=0
XDP_JSON_OUT_ENABLE=0
XDP_NF_ACTIVE=120s
XDP_NF_IDLE=30s
XDP_NF_SCAN=1s
```

`XDP_NF_ACTIVE=120s` — рабочий дефолт для production `timer`-режима на high-load mirror. Короткое значение вроде `15s` сильно размножает строки: долгоживущий flow переэкспортируется каждые 15 секунд, что увеличивает `flows_raw` ingest, число parts и ClickHouse merge I/O. На `m61` переход `15s -> 120s` снизил поток строк примерно с `~100k rows/s` до `~33k rows/s` (`~3x`).

DSN должен использовать ClickHouse native endpoint. Пароль с особыми символами
лучше URL-encode.

Перед финальным cutover заменить:

```bash
XDPFLOWD_SOURCE_ID=netflow
```

и убедиться, что старый `netflow` уже остановлен, иначе будет double-count.

Пока трафика нет, сервис можно подготовить, но не обязательно включать до подачи
зеркала.

---

## 9. Подготовить `dnsflowd`

```bash
cd /opt/GrapesNTA

sudo mkdir -p /etc/dnsflowd
sudo cp deploy/systemd/dnsflowd.env.example /etc/dnsflowd/dnsflowd.env
sudo chmod 0600 /etc/dnsflowd/dnsflowd.env
sudoedit /etc/dnsflowd/dnsflowd.env
```

Минимально выставить:

```bash
REPO_ROOT=/opt/GrapesNTA
IFACE=ens1np0

DNSFLOWD_SOURCE_ID=dns-m61
DNS_CH_DSN=clickhouse://develop:***@95.215.1.30:6124/default
DNS_CH_TABLE=default.dns_log
DNS_CH_ANSWERS_TABLE=default.dns_answers
DNS_CH_SAMPLER_ADDR=95.215.0.15

DNS_CH_RAW_ENABLED=1
DNS_CH_ANSWERS_ENABLED=1
DNS_CH_RAW_BATCH_SIZE=20000
DNS_CH_ANSWERS_BATCH_SIZE=20000
DNS_CH_RAW_QUEUE_SIZE=65536
DNS_CH_ANSWERS_QUEUE_SIZE=262144
DNS_CH_RAW_WRITERS=1
DNS_CH_ANSWERS_WRITERS=2

DNS_CAPTURE_BATCH_SIZE=1000
DNS_CAPTURE_FLUSH_INTERVAL=100ms
DNS_CH_FLUSH_INTERVAL=1s
DNS_HEALTH_INTERVAL=1m
```

Важно: если `xdpflowd` стоит на том же интерфейсе с `XDP_ACTION=drop`, включить
`XDP_DNS_PASSTHROUGH=1`, иначе `dnsflowd` не увидит UDP/53.

Перед финальным cutover заменить:

```bash
DNSFLOWD_SOURCE_ID=dns-netflow
```

и убедиться, что старый `dnsflowd` на `netflow` уже остановлен.

---

## 10. Подготовить `bmpgrapes`

Если `m61` полностью заменяет старый `netflow`, нужно также подготовить BMP
collector. До переключения роутеров BMP-сервис можно установить, но не включать
или слушать без активных peers.

Сборка:

```bash
cd /opt/GrapesNTA
make build-bmp
ls -lh bin/bmpgrapes
```

Применить BMP DDL:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '***' \
  --database default --multiquery < deploy/clickhouse/bmp.sql
```

Env:

```bash
sudo mkdir -p /etc/bmpgrapes
sudo cp deploy/systemd/bmpgrapes.env.example /etc/bmpgrapes/bmpgrapes.env
sudo chmod 0600 /etc/bmpgrapes/bmpgrapes.env
sudoedit /etc/bmpgrapes/bmpgrapes.env
```

Минимально:

```bash
REPO_ROOT=/opt/GrapesNTA
BMPGRAPES_BIN=${REPO_ROOT}/bin/bmpgrapes
BMP_LISTEN=0.0.0.0:5000
BMP_CH_DSN=clickhouse://develop:***@95.215.1.30:6124/default
BMP_CH_EVENTS_TABLE=default.bmp_route_events
BMP_CH_PEERS_TABLE=default.bmp_peers
BMP_CH_BATCH_SIZE=1000
BMP_CH_FLUSH_INTERVAL=1s
BMP_CH_QUEUE_SIZE=4096
BMP_CH_QUEUE_MODE=block
BMP_HEALTH_REQUIRE_ACTIVE_PEER=false
```

Перед финальным cutover:

- открыть TCP/5000 до `m61`;
- перенастроить BMP station на роутерах со старого `netflow` на `m61`;
- после ожидаемой первой BMP-сессии можно включить
  `BMP_HEALTH_REQUIRE_ACTIVE_PEER=true`.

Проверка:

```bash
journalctl -u bmpgrapes -n 100 --no-pager

clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '***' --query "
SELECT router_ip, peer_ip, peer_asn, event_type, max(ts) AS last_seen
FROM default.bmp_peers
WHERE ts >= now() - INTERVAL 1 HOUR
GROUP BY router_ip, peer_ip, peer_asn, event_type
ORDER BY last_seen DESC
FORMAT PrettyCompact
"
```

---

## 11. Подготовить RIR / Geo / ASN / BGP loaders

На старом окружении также используются загрузчики справочников. Если `m61`
заменяет сервер целиком, подготовить systemd env/timers:

| Компонент | Что делает | Файлы |
|-----------|------------|-------|
| `geoloaderd` | скачивает RIR delegated files, наполняет `geo_prefix_country` и `asn_registry` | `geoloaderd.*` |
| `asn-names-loader` | обогащает ASN names через Team Cymru | `asn-names-loader.*` |
| `bgp-origin-refresh` | строит `bgp_prefix_origin_current` из `bmp_route_events` | `bgp-origin-refresh.*` |

Geo/RIR:

```bash
sudo mkdir -p /etc/geoloaderd
sudo cp deploy/systemd/geoloaderd.env.example /etc/geoloaderd/geoloaderd.env
sudo chmod 0600 /etc/geoloaderd/geoloaderd.env
sudoedit /etc/geoloaderd/geoloaderd.env
```

Минимально:

```bash
GEOLOADERD_CH_HOST=95.215.1.30
GEOLOADERD_CH_PORT=6124
GEOLOADERD_CH_USER=develop
GEOLOADERD_CH_PASSWORD=***
GEOLOADERD_CH_DATABASE=default
GEOLOADERD_CACHE_DIR=/var/lib/geoloaderd/cache
```

ASN names:

```bash
sudo mkdir -p /etc/asn-names-loader
sudo cp deploy/systemd/asn-names-loader.env.example /etc/asn-names-loader/asn-names-loader.env
sudo chmod 0600 /etc/asn-names-loader/asn-names-loader.env
```

BGP origin refresh:

```bash
sudo mkdir -p /etc/bgp-origin-refresh
sudo cp deploy/systemd/bgp-origin-refresh.env.example /etc/bgp-origin-refresh/bgp-origin-refresh.env
sudo chmod 0600 /etc/bgp-origin-refresh/bgp-origin-refresh.env
sudoedit /etc/bgp-origin-refresh/bgp-origin-refresh.env
```

Минимально:

```bash
BGPORIGIN_CH_HOST=95.215.1.30
BGPORIGIN_CH_PORT=6124
BGPORIGIN_CH_USER=develop
BGPORIGIN_CH_PASSWORD=***
BGPORIGIN_CH_DATABASE=default
```

Установка units/timers:

```bash
sudo cp deploy/systemd/geoloaderd.service deploy/systemd/geoloaderd.timer /etc/systemd/system/
sudo cp deploy/systemd/asn-names-loader.service deploy/systemd/asn-names-loader.timer /etc/systemd/system/
sudo cp deploy/systemd/bgp-origin-refresh.service deploy/systemd/bgp-origin-refresh.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

Перед включением timers сделать ручной dry/smoke запуск каждого сервиса и
проверить journal. Не включать параллельно два одинаковых refresh-процесса на
старом и новом серверах, если они пишут в одни и те же staging/target таблицы.

---

## 12. Установить systemd units

```bash
cd /opt/GrapesNTA

sudo cp deploy/systemd/xdpflowd-exec.sh /usr/local/sbin/xdpflowd-exec.sh
sudo chmod +x /usr/local/sbin/xdpflowd-exec.sh
sudo cp deploy/systemd/xdpflowd.service /etc/systemd/system/xdpflowd.service

sudo cp deploy/systemd/dnsflowd-exec.sh /usr/local/sbin/dnsflowd-exec.sh
sudo chmod +x /usr/local/sbin/dnsflowd-exec.sh
sudo cp deploy/systemd/dnsflowd.service /etc/systemd/system/dnsflowd.service

sudo systemctl daemon-reload
```

Пока зеркало не подключено, можно оставить сервисы disabled:

```bash
sudo systemctl disable xdpflowd dnsflowd 2>/dev/null || true
```

---

## 13. Когда подключат зеркало

Сначала не запускать XDP. Проверить чистый входящий baseline:

```bash
IF=ens1np0

ip link set "$IF" up
ip link set "$IF" promisc on

ethtool "$IF" | egrep 'Speed|Duplex|Link detected'

A_RX=$(cat /sys/class/net/$IF/statistics/rx_packets)
A_BYTES=$(cat /sys/class/net/$IF/statistics/rx_bytes)
A_DROP=$(cat /sys/class/net/$IF/statistics/rx_dropped)
A_FIFO=$(cat /sys/class/net/$IF/statistics/rx_fifo_errors)
sleep 60
B_RX=$(cat /sys/class/net/$IF/statistics/rx_packets)
B_BYTES=$(cat /sys/class/net/$IF/statistics/rx_bytes)
B_DROP=$(cat /sys/class/net/$IF/statistics/rx_dropped)
B_FIFO=$(cat /sys/class/net/$IF/statistics/rx_fifo_errors)

echo "rx_pps=$(( (B_RX-A_RX)/60 ))"
echo "rx_gbps=$(awk "BEGIN { printf \"%.3f\", (($B_BYTES-$A_BYTES)*8/60)/1000000000 }")"
echo "rx_dropped_delta=$((B_DROP-A_DROP))"
echo "rx_fifo_delta=$((B_FIFO-A_FIFO))"
```

Если `rx_dropped_delta = 0` и `rx_fifo_delta = 0`, можно пробовать `xdpflowd`
в `generic` режиме.

Если уже без XDP есть drops/fifo, только тогда применять NIC tuning:

```bash
IF=ens1np0
ethtool -G "$IF" rx 8192 tx 8192
ethtool -C "$IF" adaptive-rx off adaptive-tx off rx-usecs 64 rx-frames 128 tx-usecs 64 tx-frames 128
```

Для `mlx5_core` не переносить слепо старый профиль `rx-usecs 512 rx-frames 512`
с `mlx4_en`. Начинать с умеренных значений и смотреть потери/CPU.

---

## 14. Первый XDP smoke test

Первый запуск: `generic`, короткое окно, смотреть логи и counters.

```bash
sudo systemctl start dnsflowd
sudo systemctl start xdpflowd

sudo journalctl -u xdpflowd -f
sudo journalctl -u dnsflowd -f
```

Проверить XDP attach:

```bash
ip -details link show dev ens1np0 | sed -n '1,30p'
```

Проверить ClickHouse:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '***' --query "
SELECT
    source_id,
    count() AS rows,
    sum(packets) AS packets,
    sum(bytes) AS bytes
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 5 MINUTE
  AND source_id IN ('xdp-m61')
GROUP BY source_id
FORMAT PrettyCompact
"
```

Проверить, что включился классификатор. В логах должны быть строки
`traffic classifier enabled` и `traffic classifier refreshed` с
`has_local_config=true`:

```bash
journalctl -u xdpflowd --since "10 minutes ago" --no-pager -o cat \
  | egrep 'traffic classifier|classifier refreshed|flow source configured'
```

Проверить свежую классификацию в `flows_raw`:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '***' --query "
SELECT
    direction,
    src_role,
    dst_role,
    count() AS rows,
    round(sum(bytes)/1e9, 2) AS gb
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 15 MINUTE
  AND source_id = 'xdp-m61'
GROUP BY
    direction,
    src_role,
    dst_role
ORDER BY gb DESC
FORMAT PrettyCompact
"
```

Если почти всё в `direction = 'unknown'`, а `src_role` / `dst_role` пустые,
значит `XDP_CLASSIFIER` не включён или не смог прочитать таблицы
`net_l3_prefixes_enabled` / `net_l2_vlans_enabled` / `bgp_prefix_origin_current`.

DNS:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '***' --query "
SELECT
    source_id,
    count() AS rows,
    countIf(is_response = 0) AS queries,
    countIf(is_response = 1) AS responses
FROM default.dns_log
WHERE ts >= now('UTC') - INTERVAL 5 MINUTE
  AND source_id = 'dns-m61'
GROUP BY source_id
FORMAT PrettyCompact
"
```

Критерии остановки/rollback:

- растут `rx_fifo_errors` или `rx_dropped`;
- `xdpflowd` пишет spool, но `records_acked` не растёт;
- нет строк в ClickHouse при живом трафике;
- `dnsflowd` пишет `queue full` или `health degraded`.

---

## 15. Troubleshooting: после cutover пропала классификация

Симптом: после замены сервера на графике есть «Всего», но `in/out/transit/internal`
упали к нулю или почти весь трафик стал `unknown`.

Самая частая причина: `xdpflowd` пишет в `flows_raw`, но запущен без traffic
classifier. У `xdpflowd` classifier по умолчанию выключен (`XDP_CLASSIFIER=0`).

Проверить env на collector:

```bash
grep -E '^(XDP_CLASSIFIER|XDP_CLASSIFIER_|XDP_CH_DSN|XDPFLOWD_SOURCE_ID)' \
  /etc/xdpflowd/xdpflowd.env
```

Проверить логи:

```bash
journalctl -u xdpflowd --since "30 minutes ago" --no-pager -o cat \
  | egrep 'traffic classifier|classifier refresh|classifier refreshed|flow source configured'
```

Нормально:

```text
traffic classifier enabled
traffic classifier refreshed ... l3_prefixes=... has_local_config=true
```

Проверить свежие данные:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '***' --query "
SELECT
    direction,
    src_role,
    dst_role,
    count() AS rows,
    round(sum(bytes)/1e9, 2) AS gb
FROM default.flows_raw
WHERE time_received_ns >= now() - INTERVAL 15 MINUTE
  AND source_id = 'netflow'
GROUP BY
    direction,
    src_role,
    dst_role
ORDER BY gb DESC
FORMAT PrettyCompact
"
```

Если почти всё:

```text
direction = unknown
src_role = ''
dst_role = ''
```

включить classifier:

```bash
sudo sed -i 's/^XDP_CLASSIFIER=.*/XDP_CLASSIFIER=1/' /etc/xdpflowd/xdpflowd.env
sudo systemctl restart xdpflowd
sleep 10

journalctl -u xdpflowd -n 100 --no-pager -o cat \
  | egrep 'traffic classifier|classifier refreshed|xdpflowd started|flow source configured'
```

Если после включения classifier сервис не стартует, проверить доступность таблиц:

```bash
clickhouse-client --host 95.215.1.30 --port 6124 --user develop --password '***' --query "
SELECT 'l3' AS table_name, count() FROM default.net_l3_prefixes_enabled
UNION ALL
SELECT 'l2' AS table_name, count() FROM default.net_l2_vlans_enabled
UNION ALL
SELECT 'bgp' AS table_name, count() FROM default.bgp_prefix_origin_current
FORMAT PrettyCompact
"
```

Важно: уже записанные строки с `direction='unknown'` сами не
переклассифицируются. После фикса новые минуты пойдут правильно, а для истории
за время неправильной работы нужен отдельный rebuild/backfill агрегатов или
перезапись raw enrichment за выбранный период.

---

## 16. Native XDP test на mlx5_core

На `m61` можно отдельно попробовать native XDP, потому что карта `mlx5_core`.
Но делать это только после успешного `generic` smoke test.

Порядок:

1. Сохранить baseline без XDP за 5 минут.
2. Запустить `XDP_MODE=native` на короткое окно.
3. Смотреть `rx_dropped`, `rx_fifo_errors`, `journalctl -k`, `journalctl -u xdpflowd`.
4. Если есть потери или link flap — вернуться на `generic`.

Не переносить выводы старого `sel` один-в-один: там проблема была в native path
драйвера `mlx4_en`. На `mlx5_core` native может работать штатно, но это нужно
подтвердить тестом.

### Результат теста на m61 (2026-06-10, mlx5_core / ConnectX-4)

native подтверждён как рабочий и **более выгодный**, оставлен основным режимом.

Условия: live mirror ~2.8 Mpps / ~18 Gbps, `XDP_ACTION=drop`,
`FLOWS_MAP_SIZE=12M`, `XDP_CH_WRITERS=12`.

| Метрика | generic | native |
|---|---|---|
| system `%soft` (softirq) | ~12.0% | ~6.8% |
| system `%idle` | ~78.7% | ~87.0% |
| xdpflowd `%CPU` | ~281% | ~286% |
| dnsflowd `%CPU` | ~53% | ~54% |
| insert_errs / lag_segments | 0 / 0 | 0 / 0 |
| map_full | 0 | 0 |

Проверки железа под native (30s дельты):
- `rx_discards_phy_delta` = 21 pps при 2.8 Mpps → 0.00075% (микробёрсты, не системная потеря).
- `rx_out_of_buffer_delta` = 0 → software RX ring справляется.
- `rx_steer_missed_packets` большой, но на mirror/promisc-порту это норма и безвреден
  (пакеты не матчат RSS-steering и идут в default; XDP их всё равно видит и дропает).

Важно про счётчики в native + `XDP_ACTION=drop`:
- `/sys/class/net/$IF/statistics/rx_packets` и `rx_bytes` НЕ отражают XDP-дропнутый
  трафик (пакет дропается в драйвере до skb). Реальный объём смотреть по:
  - `ethtool -S $IF` → сумма per-queue `rxN_xdp_drop` (НЕ складывать с общим
    `rx_xdp_drop`, иначе двойной счёт);
  - `journalctl -u xdpflowd` → `total_packets` / `accounted_packets`;
  - наполнение `flows_raw` в ClickHouse.

Вывод: на `mlx5_core` native снижает softirq почти вдвое и освобождает ~8% CPU
системы относительно generic, без потерь на железе. Для `m61` это дефолт.
Опционально `ethtool -G $IF rx 8192` убирает остаточные ~21 pps PHY-микробёрстов.

---

## 17. Снижение потерь flow на высоких скоростях (map_full)

### Симптом

`journalctl -u xdpflowd` показывает растущий `map_full_total` (например 1.6 млрд) и
`map_full_delta > 0` с `xdpflowd health degraded`. В ClickHouse при этом виден
недосчёт трафика. Особенно проявляется после включения классификатора
(`XDP_CLASSIFIER=1`) и под флудом со спуфленными source-IP.

### Причина

1. **Тип карты.** Раньше `flows` был `BPF_MAP_TYPE_HASH`: при заполнении вставка
   нового flow падает (`bump_stat(STAT_MAP_FULL)`) и его байты **вообще не
   учитываются**. Это прямой источник потерь.
2. **Скорость дренажа.** Экспорт-тик каждую секунду обходил **всю** карту
   итератором (`Iterate()` = per-key `GET_NEXT_KEY`+`LOOKUP`) и потом per-key
   `LookupAndDelete`. На 12M записей это десятки млн syscall за цикл — не
   укладывается в 1 с, карта переполняется быстрее, чем дренируется.

### Фикс (актуальный безопасный baseline)

1. **Timer/atomic остаётся production baseline.** Flow экспортируется по
   `idle/active` timeout, как в исходной NetFlow-семантике.
2. **Streaming timer drain.** Expired-flow export теперь отдаёт данные чанками
   (`flowStreamChunk`), а не собирает все expired flow в один огромный `[]flowKV`.
   Это сохраняет старую семантику, но убирает десятки GB transient heap на
   высококардинальных зеркалах.
3. **LRU/размер карты — отдельный рычаг.** Если `map_full_delta` остаётся
   ненулевым, сначала увеличивайте `FLOWS_MAP_SIZE` и снижайте стоимость
   timer-drain, а не включайте постоянный full-drain.

`XDP_DRAIN_MODE=batch` оставлен только как ручной/экспериментальный режим. Не
делайте его production default: постоянный full-drain меняет семантику flow и
может резко увеличить поток строк в ClickHouse.

### Что выставить на m61

В `/etc/xdpflowd/xdpflowd.env`:

```bash
XDP_DRAIN_MODE=timer
XDP_AGG_ENABLE=0
XDP_CH_SPOOL_SHUTDOWN_DRAIN=0s   # быстрые рестарты: backlog остаётся в spool
XDP_FINAL_FLUSH=0                 # быстрые рестарты: не сканировать всю BPF map на stop
```

`XDP_FINAL_FLUSH=0` означает, что при `systemctl restart` активные flow, которые
ещё не дошли до idle/active timeout, не будут принудительно выгружены перед
выходом. Это осознанный operational trade-off ради быстрого рестарта. Для
планового полного drain можно временно поставить `XDP_FINAL_FLUSH=1`.

Пересборка с увеличенной картой (пример для RAM ≥ 64 GB):

```bash
cd /opt/GrapesNTA
git pull
free -g                              # убедиться в запасе RAM
make clean
make bpf FLOWS_MAP_SIZE=24000000     # 24M ≈ 4-5 GB
make build
systemctl restart xdpflowd
```

### Проверка после рестарта

```bash
journalctl -u xdpflowd -n 80 --no-pager | grep -E 'stats|netflow records|spool pipeline|health|flow drainer|map_full'
```

Ожидаем:
- `flow drainer: using atomic LookupAndDelete ...`;
- нет `batch full-drain` и нет `flow aggregation enabled`;
- `lag_segments` около 0-1, `insert_errs_delta=0`;
- `map_full_delta=0` или снижается после увеличения карты;
- тождество учёта держится: `total_packets == accounted + parse_errors + map_full + non_ip_pass`.

### Откат

Если экспериментальный `batch` был включён, верните:

```bash
XDP_DRAIN_MODE=timer
XDP_AGG_ENABLE=0
```

## 18. Перегрузка ClickHouse / рост спула

### Симптом

`map_full=0` (потерь flow нет), но в логах `xdpflowd health degraded` с быстро
растущими `writer_lag_rows` и `lag_segments`; спул-сегменты копятся на диске,
`records_spooled` >> `records_acked`. ClickHouse не успевает принимать вставки —
не из-за обрывов (`insert_errs=0`), а из-за **объёма строк**.

### Причина

На горячем ingest-пути ClickHouse синхронно считает materialized views. При
большом flow rate это даёт высокий fan-out: один `INSERT flows_raw` заставляет
перечитывать/агрегировать десятки миллионов строк во view.

### Диагностика

```bash
clickhouse-client ... -q "
SELECT
    view_name,
    count() AS inserts,
    sum(read_rows) AS read_rows,
    sum(written_rows) AS written_rows,
    round(avg(view_duration_ms)) AS avg_ms,
    round(sum(view_duration_ms)) AS total_ms
FROM system.query_views_log
WHERE event_time >= now() - INTERVAL 10 MINUTE
GROUP BY view_name
ORDER BY total_ms DESC"
```

Если сверху `traffic_pair_*` / `traffic_talker_*`, их нельзя держать тяжёлыми
синхронными MV на production ingest.

### Быстрое восстановление

Отцепить **все** `traffic_*` sync MV (данные в `flows_raw` сохраняются):

```bash
clickhouse-client ... --multiquery < deploy/clickhouse/detach_traffic_mvs.sql
```

Проверка:

```bash
clickhouse-client ... -q "
SELECT name FROM system.tables
WHERE database='default' AND engine='MaterializedView' AND name LIKE 'traffic_%'"
```

Должно быть пусто.

Проверка:

```bash
clickhouse-client ... -q "
SELECT count() inserts, round(avg(query_duration_ms)) avg_ms,
       round(quantile(0.95)(query_duration_ms)) p95_ms
FROM system.query_log
WHERE event_time >= now() - INTERVAL 3 MINUTE
  AND type='QueryFinish' AND query_kind='Insert'
  AND query ILIKE '%flows_raw%'"
```

### Постоянное решение (production на m61)

Все `traffic_*` агрегаты считаются **асинхронно** на коллекторе:

- `scripts/traffic_rollup_async.py` + `scripts/traffic_rollup_jobs.py` (15 jobs)
- `deploy/clickhouse/traffic_rollup_state.sql` — watermark
- `deploy/clickhouse/detach_traffic_mvs.sql` — отцепить legacy sync MV
- `deploy/systemd/traffic-rollups.timer` — каждую минуту, 1 bucket/job

Hot path = только `INSERT flows_raw`. Ожидаемый лаг UI-агрегатов: **5–10 минут**.

Полная процедура: [`CLICKHOUSE_DB_SETUP_RUNBOOK.md`](CLICKHOUSE_DB_SETUP_RUNBOOK.md) §7.

```bash
# после lag_segments ~ 0
ch --multiquery < deploy/clickhouse/traffic_rollup_state.sql
ch --multiquery < deploy/clickhouse/detach_traffic_mvs.sql
sudo cp deploy/systemd/traffic-rollups.env.example /etc/grapesnta/traffic-rollups.env
sudo cp deploy/systemd/traffic-rollups.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now traffic-rollups.timer
```

