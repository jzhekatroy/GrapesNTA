# Runbook: постоянный `xdpflowd` на `sel`

Операционный сценарий перевода сервера `sel` с `ipt_NETFLOW` + `goflow2` на постоянный **`xdpflowd`** под **systemd**, с сохранением локального **`nfcapd`** и быстрым ручным откатом.

См. также:

- NIC / kernel 6.12 baseline: [`KERNEL_6_12_BASELINE.md`](KERNEL_6_12_BASELINE.md)
- ClickHouse / spool: [`CLICKHOUSE_FLOWS_RAW.md`](CLICKHOUSE_FLOWS_RAW.md)

## Целевой профиль (prod)

- `XDP_MODE=generic` (на `sel` + `mlx4_en` + kernel 6.12 native XDP нестабилен)
- `XDP_ACTION=drop` (только зеркальный интерфейс; обычно `enp5s0d1`)
- `NF_DSTS=127.0.0.1:9996` — локальный `nfcapd` без изменений
- Прямой INSERT в ClickHouse с **durable spool** (`XDP_CH_SPOOL_MODE=required`)
- Контейнер `goflow2` (**`kcg-goflow2-1`**) останавливается, чтобы не жечь CPU и не дублировать запись в БД

## Файлы в репозитории

| Файл | Назначение |
|------|------------|
| [`deploy/sel/xdpflowd.env.example`](deploy/sel/xdpflowd.env.example) | Шаблон `/etc/xdpflowd/sel.env` |
| [`deploy/sel/xdpflowd-exec.sh`](deploy/sel/xdpflowd-exec.sh) | Обёртка: читает env и запускает `xdpflowd` (вызывается из systemd) |
| [`deploy/sel/xdpflowd.service`](deploy/sel/xdpflowd.service) | Шаблон unit-файла (пути `/opt/GrapesNTA` подменяются при установке) |
| [`scripts/prod_enable_xdpflowd_sel.sh`](scripts/prod_enable_xdpflowd_sel.sh) | Включить постоянный режим |
| [`scripts/prod_rollback_legacy_sel.sh`](scripts/prod_rollback_legacy_sel.sh) | Быстрый откат на legacy |

После включения:

- state + iptables backup: `/root/xdpflowd_sel_permanent_state.env`
- полный дамп iptables: `/root/iptables-save-before-sel-permanent-<TS>.txt`

## Перед включением

1. Собрать актуальный код на `sel`:

   ```bash
   cd /opt/GrapesNTA   # или ваш путь к checkout
   make clean && make && make bpf
   ```

2. Восстановить **известный хороший** профиль NIC для зеркала (после reboot параметры часто сбрасываются):

   ```bash
   ip link set enp5s0d1 promisc on
   ethtool -L enp5s0d1 rx 16 tx 24
   ethtool -G enp5s0d1 rx 8192
   ethtool -C enp5s0d1 adaptive-rx off rx-usecs 512 rx-frames 512
   ethtool -A enp5s0d1 rx on tx on
   ```

3. Подготовить secrets:

   ```bash
   sudo mkdir -p /etc/xdpflowd
   sudo cp deploy/sel/xdpflowd.env.example /etc/xdpflowd/sel.env
   sudo chmod 0600 /etc/xdpflowd/sel.env
   sudoedit /etc/xdpflowd/sel.env
   ```

   Обязательно задать **`XDP_CH_DSN`** (native порт, часто `9000`) и **`XDP_CH_TABLE`** (например `default.flows_raw`).
   Для привязки к хосту можно раскомментировать и выставить `XDPFLOWD_EXPECT_HOST_SHORT=sel` в том же файле (также проверяется обёрткой `xdpflowd-exec.sh`).

4. (Рекомендуется) короткая репетиция 2–5 минут через `prod_ab_swap.sh` с тем же профилем, что и в `sel.env`.

## Включение постоянного режима

```bash
cd /opt/GrapesNTA
sudo ./scripts/prod_enable_xdpflowd_sel.sh
```

Скрипт:

- найдёт **ровно одно** правило `PREROUTING … -j NETFLOW` для `-i <IFACE>`;
- снимет его;
- остановит контейнеры из `XDP_GOFLOW2_CONTAINERS` в `sel.env`;
- установит `/etc/systemd/system/xdpflowd.service` (с подстановкой `REPO_ROOT` из текущего checkout);
- выполнит `systemctl enable --now xdpflowd`.

### Логи

```bash
journalctl -u xdpflowd -f
systemctl status xdpflowd --no-pager
```

### Smoke checks

- **Локальный NetFlow / VLAN / MAC** (путь к nfcapd подставить свой):

  ```bash
  nfdump -r /storage/nfdump/$(date +%Y-%m-%d)/<nfcapd.file> -o raw -c 5
  ```

- **ClickHouse** (рост `packets` / `bytes` за последние N минут по `time_received_ns`):

  ```bash
  clickhouse-client --host ... --query "SELECT count() AS rows, sum(packets), sum(bytes) FROM default.flows_raw WHERE time_received_ns > now64(9) - INTERVAL 5 MINUTE"
  ```

- **Потери на карте** (должно оставаться около «чистого» baseline на `sel`):

  ```bash
  watch -n1 "cat /sys/class/net/enp5s0d1/statistics/rx_fifo_errors"
  ```

- **Spool** — по логам при `systemctl stop` / рестарте ищите строки наподобие
  `clickhouse spool pipeline closed` с полями `records_spooled`, `records_acked`, `insert_errs`.

Критерии **немедленного ручного rollback**: рост `rx_fifo_errors` сверх baseline, «тишина» в `nfcapd`, отсутствие INSERT в ClickHouse при живом сервисе, рост spool без `acked`, циклические падения `xdpflowd`.

## Быстрый откат (legacy)

Одна команда:

```bash
sudo /opt/GrapesNTA/scripts/prod_rollback_legacy_sel.sh
```

Ожидаемое состояние после отката:

- `xdpflowd` остановлен и отключён (`systemctl` не обязан удалять unit — он остаётся на диске, но disabled);
- XDP снят best-effort (`ip link set dev enp5s0d1 xdp off`);
- правило `ipt_NETFLOW` возвращено;
- контейнеры `goflow2` из state запущены;
- **spool не удаляется** — при необходимости досыл/анализ отдельно.

Если state потерян, см. аварийный restore:

[`scripts/prod_restore.sh`](scripts/prod_restore.sh) с `--full-restore` на файл `/root/iptables-save-before-sel-permanent-*.txt`.

## Примечания

- `TimeoutStopSec=600` в unit рассчитан на финальный flush большой flow map + drain spool; при ещё более тяжёлых хостах может понадобиться увеличить.
- Для изменения флагов правьте `/etc/xdpflowd/sel.env`, затем `sudo systemctl restart xdpflowd`.
