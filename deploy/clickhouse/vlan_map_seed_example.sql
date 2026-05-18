-- Example manual seed for default.vlan_map.
--
-- Edit labels/kinds before applying if needed. Re-running this file appends new
-- ReplacingMergeTree versions; default.vlan_map_enabled exposes the latest rows.

INSERT INTO default.vlan_map
(vlan_id, kind, label, operator_id, source, enabled, updated_at)
VALUES
    (105, 'uplink', 'Transroute.spb', '', 'manual', 1, now()),
    (106, 'uplink', 'Transroute.m61', '', 'manual', 1, now()),
    (262, 'uplink', 'Transroute.msk', '', 'manual', 1, now()),
    (263, 'uplink', '', '', 'manual', 1, now()),
    (345, 'ix', 'Eurasia.ix', '', 'manual', 1, now()),
    (444, 'ix', 'Piterix.spb', '', 'manual', 1, now()),
    (445, 'ix', 'Piterix.msk', '', 'manual', 1, now()),
    (447, 'ix', 'Piterix.hls', '', 'manual', 1, now()),
    (452, 'ix', 'Piterix.fkf', '', 'manual', 1, now());
