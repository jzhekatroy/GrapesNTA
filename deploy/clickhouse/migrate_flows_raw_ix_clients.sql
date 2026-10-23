-- IX-стороны потока отдельно от src_client / dst_client.
-- Старые колонки по-прежнему пишутся только с порта клиента, поэтому суммы
-- кабинета не задваиваются. Новые колонки пустые, пока учёт IX выключен.
-- ADD COLUMN не переписывает старые данные. Повторный запуск безопасен.
-- Коллектор с этими колонками в INSERT можно запускать только после миграции.
--
-- Читатели на время смены раскладки смотрят в flows_all. У обёртки свой список
-- колонок, снятый при создании: колонка, добавленная только в flows_raw, из
-- flows_all не видна, и сводка падает UNKNOWN_IDENTIFIER ещё до проверки,
-- что IX выключен. flows_v1 — прежняя таблица под той же обёрткой, её может
-- не быть: неизвестная таблица при накате схемы пропускается.

ALTER TABLE default.flows_raw
    ADD COLUMN IF NOT EXISTS ix_src_client LowCardinality(String) DEFAULT '' AFTER dst_client;

ALTER TABLE default.flows_raw
    ADD COLUMN IF NOT EXISTS ix_dst_client LowCardinality(String) DEFAULT '' AFTER ix_src_client;

ALTER TABLE default.flows_v1
    ADD COLUMN IF NOT EXISTS ix_src_client LowCardinality(String) DEFAULT '' AFTER dst_client;

ALTER TABLE default.flows_v1
    ADD COLUMN IF NOT EXISTS ix_dst_client LowCardinality(String) DEFAULT '' AFTER ix_src_client;

ALTER TABLE default.flows_all
    ADD COLUMN IF NOT EXISTS ix_src_client LowCardinality(String) DEFAULT '' AFTER dst_client;

ALTER TABLE default.flows_all
    ADD COLUMN IF NOT EXISTS ix_dst_client LowCardinality(String) DEFAULT '' AFTER ix_src_client;
