-- Индекс по эффективному VLAN и по src_asn для разбора трафика.
-- multiIf в условии ClickHouse не отсекает гранулы, поэтому VLAN хранится
-- отдельной материализованной колонкой, а индекс стоит на ней.
-- ADD COLUMN / ADD INDEX не переписывают старые куски. MATERIALIZE COLUMN
-- и MATERIALIZE INDEX переписали бы всю flows_raw и здесь намеренно нет.
-- Повторный запуск безопасен.

ALTER TABLE default.flows_raw
    DROP INDEX IF EXISTS idx_obs_eff_vlan;

ALTER TABLE default.flows_raw
    ADD COLUMN IF NOT EXISTS eff_vlan UInt16 MATERIALIZED multiIf(
        direction = 'out' AND src_vlan != 0, src_vlan,
        direction = 'in' AND dst_vlan != 0, dst_vlan,
        src_vlan != 0, src_vlan,
        dst_vlan
    );

ALTER TABLE default.flows_raw
    ADD INDEX IF NOT EXISTS idx_obs_eff_vlan eff_vlan TYPE set(0) GRANULARITY 4;

ALTER TABLE default.flows_raw
    ADD INDEX IF NOT EXISTS idx_obs_src_asn src_asn TYPE set(0) GRANULARITY 4;
