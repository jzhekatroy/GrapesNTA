ALTER TABLE default.roles
    ADD COLUMN IF NOT EXISTS start_page String DEFAULT 'dashboard';
