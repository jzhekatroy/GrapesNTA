ALTER TABLE default.observation_runs
    ADD COLUMN IF NOT EXISTS email_status String DEFAULT '',
    ADD COLUMN IF NOT EXISTS email_to String DEFAULT '',
    ADD COLUMN IF NOT EXISTS email_error String DEFAULT '';
