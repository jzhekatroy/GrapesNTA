ALTER TABLE default.observations
    ADD COLUMN IF NOT EXISTS edited_at DateTime64(3) DEFAULT created_at;
