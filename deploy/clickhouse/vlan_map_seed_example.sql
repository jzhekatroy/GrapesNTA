-- Example manual seed for default.vlan_map.
--
-- Edit labels/attachment kinds before applying if needed. Re-running this file appends new
-- ReplacingMergeTree versions; default.vlan_map_enabled exposes the latest rows.

INSERT INTO default.vlan_map
(vlan_id, attachment_kind, boundary, label, operator_id, source, enabled, updated_at)
VALUES
    (105, 'uplink', 'external', 'Transroute.spb', '', 'manual', 1, now()),
    (106, 'uplink', 'external', 'Transroute.m61', '', 'manual', 1, now()),
    (262, 'uplink', 'external', 'Transroute.msk', '', 'manual', 1, now()),
    (263, 'uplink', 'external', '', '', 'manual', 1, now()),
    (345, 'ix', 'external', 'Eurasia.ix', '', 'manual', 1, now()),
    (444, 'ix', 'external', 'Piterix.spb', '', 'manual', 1, now()),
    (445, 'ix', 'external', 'Piterix.msk', '', 'manual', 1, now()),
    (447, 'ix', 'external', 'Piterix.hls', '', 'manual', 1, now()),
    (452, 'ix', 'external', 'Piterix.fkf', '', 'manual', 1, now());
