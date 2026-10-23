ALTER TABLE default.roles
    ADD COLUMN IF NOT EXISTS attack_alert UInt8 DEFAULT 0;
