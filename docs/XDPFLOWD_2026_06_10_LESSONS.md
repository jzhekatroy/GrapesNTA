# xdpflowd 2026-06-10 Lessons Learned

## Что не повторять

Не считать `batch full-drain` каждые несколько секунд правильным основным режимом
работы коллектора.

Этот путь был неверным:

- включить постоянный `XDP_DRAIN_MODE=batch`;
- снимать всю BPF flow map каждые 5 секунд;
- пытаться сгладить это userspace-агрегацией;
- затем рассматривать sampling как основное лечение.

Почему это плохо:

- full-drain меняет семантику формирования flow и резко увеличивает поток строк
  в ClickHouse;
- userspace-агрегация почти не помогает при большом количестве коротких
  уникальных flow;
- ClickHouse начинает получать намного больше строк, чем в старом
  timer/atomic-режиме, и spool начинает расти;
- sampling противоречит требованию хранить все данные.

## Что выяснили

Утренний/старый режим (`atomic/timer`, без batch/agg) ближе к рабочему baseline:

- `flow drainer: using atomic LookupAndDelete`;
- нет `batch full-drain`;
- нет `flow aggregation enabled`;
- `map_full` может появляться на пиках, но ClickHouse получает более мягкий и
  близкий к исходной семантике поток flow.

Проблемы дня смешались из нескольких факторов:

- краткие сетевые ошибки до ClickHouse (`no route to host`);
- накопленный spool backlog;
- переход на batch full-drain, который изменил нагрузку;
- реальный вход около 32.5 Gbit/s и 4.2 Mpps после стабилизации;
- текущий ClickHouse перегружен синхронными materialized views.

## Правильное направление

Без sampling и без постоянного full-drain:

1. Оставить базовый режим `atomic/timer`.
2. Не включать постоянный batch full-drain на production.
3. Если нужен batch, использовать его только как аварийный/ручной клапан, а не
   как основной экспорт.
4. Оптимизировать timer/atomic путь в коде так, чтобы он был memory-bounded и не
   собирал огромные `[]flowKV` в памяти. Реализованный безопасный вариант:
   `StreamExpired` / `StreamAll` отдают expired/all flows чанками и сохраняют
   idle/active семантику.
5. Основное узкое место переносить в архитектуру ClickHouse: raw ingest отдельно,
   тяжёлые materialized views асинхронно.

## ClickHouse: реальные тяжёлые MV

Замер `system.query_views_log` за 10 минут показал главных потребителей:

| MV | avg_ms | total_ms |
| --- | ---: | ---: |
| `default.traffic_talker_1m_mv` | 1181 | 421644 |
| `default.traffic_pair_1m_mv` | 1119 | 399464 |
| `default.traffic_pair_1h_mv` | 719 | 256569 |
| `default.traffic_talker_1h_mv` | 578 | 206391 |
| `default.traffic_country_1m_mv` | 297 | 106166 |

Вывод: первым делом разгружать ClickHouse, а не менять коллектор:

- `traffic_talker_*` и `traffic_pair_*` нельзя держать тяжёлым синхронным
  fan-out на горячем ingest-пути при текущей нагрузке;
- их нужно переводить на асинхронный пересчёт из `flows_raw`;
- online на insert оставить только самые лёгкие и необходимые агрегаты.

## Быстрый checklist перед экспериментами

Перед любым новым collector-режимом сначала проверить:

```bash
journalctl -u xdpflowd -n 80 --no-pager | grep -E 'stats|netflow records|spool pipeline|health|flow drainer|map_full'
```

Считать:

- packet rate по `total_packets`;
- flow row rate по `records_spooled`;
- ClickHouse ack rate по `records_acked`;
- потери по `map_full_delta`;
- backlog по `lag_segments`.

Не делать выводы только по UI-графику или `time_received_ns`: пачки могут иметь
одинаковый timestamp, из-за чего график становится рваным.
