-- IX-стороны потока отдельно от src_client / dst_client.
-- Старые колонки по-прежнему пишутся только с порта клиента, поэтому суммы
-- кабинета не задваиваются. Новые колонки пустые, пока учёт IX выключен.
-- ADD COLUMN не переписывает старые данные. Повторный запуск безопасен.
-- Коллектор с этими колонками в INSERT можно запускать только после миграции.

ALTER TABLE default.flows_raw
    ADD COLUMN IF NOT EXISTS ix_src_client LowCardinality(String) DEFAULT '' AFTER dst_client;

ALTER TABLE default.flows_raw
    ADD COLUMN IF NOT EXISTS ix_dst_client LowCardinality(String) DEFAULT '' AFTER ix_src_client;
