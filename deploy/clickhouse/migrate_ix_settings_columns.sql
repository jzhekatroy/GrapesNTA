-- IX columns that traffic_client_ix_1m and the IX cabinet read.
-- On older stands the UI adds them only when the ERP settings page or a VLAN
-- save runs, so a stand without IX may never get them. Defaults keep IX off.
-- ADD COLUMN does not rewrite data. Safe to re-run.

ALTER TABLE default.app_erp_sync_settings
    ADD COLUMN IF NOT EXISTS ix_enabled UInt8 DEFAULT 0;

ALTER TABLE default.app_erp_sync_settings
    ADD COLUMN IF NOT EXISTS ix_mac_on_port UInt8 DEFAULT 0;

ALTER TABLE default.app_erp_sync_settings
    ADD COLUMN IF NOT EXISTS ix_scope_only UInt8 DEFAULT 0;

ALTER TABLE default.net_l2_vlans
    ADD COLUMN IF NOT EXISTS ix UInt8 DEFAULT 0;

ALTER TABLE default.net_l2_vlans
    ADD COLUMN IF NOT EXISTS ix_location String DEFAULT '';
