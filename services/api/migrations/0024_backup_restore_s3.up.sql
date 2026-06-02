-- 0024_backup_restore_s3.up.sql
-- Data tranche: scheduled backup dispatch state, restore executions, and S3
-- credential references (the secret KEY lives age-encrypted in `secrets`; only a
-- non-secret reference + the access-key id are stored on the schedule).
--
-- Expand-only: every column added is nullable / defaulted, so this is safe to apply
-- online against a populated `backup_schedules` table.

-- S3 credential references for a schedule. `s3_access_key_id` is NOT secret (it is an
-- identifier, like a username). The matching secret key is stored age-encrypted in the
-- `secrets` table and referenced by `s3_secret_id` — never as plaintext here (OWASP A02).
ALTER TABLE backup_schedules
    ADD COLUMN IF NOT EXISTS s3_region        TEXT,
    ADD COLUMN IF NOT EXISTS s3_access_key_id TEXT,
    ADD COLUMN IF NOT EXISTS s3_secret_id     UUID REFERENCES secrets(id) ON DELETE SET NULL,
    -- Bound how many successful executions to retain per schedule in addition to the
    -- age-based `retention_days`. NULL = age-only retention.
    ADD COLUMN IF NOT EXISTS retention_count  INTEGER;

-- Target container the scheduled dump runs against (resolved once at schedule creation
-- from the deployment spec; the scheduler reuses it so it never has to re-derive).
ALTER TABLE backup_schedules
    ADD COLUMN IF NOT EXISTS target_container TEXT;

-- Restore executions: one row per restore attempt. Restores are destructive, so each is
-- audited with the source execution it restored from, the engine + target it ran against,
-- and a terminal status mirroring backup_executions.
CREATE TABLE IF NOT EXISTS restore_executions (
    id UUID PRIMARY KEY,
    deployment_id UUID REFERENCES deployments(id) ON DELETE CASCADE,
    -- The backup execution whose dump we restored from.
    source_execution_id UUID REFERENCES backup_executions(id) ON DELETE SET NULL,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'success', 'failed', 'skipped')),
    db_type TEXT NOT NULL,
    target_container TEXT NOT NULL,
    location TEXT,                            -- S3 key / volume path the dump came from
    error TEXT,
    requested_by_principal_id UUID,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_restore_executions_deployment
    ON restore_executions (deployment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_restore_executions_source
    ON restore_executions (source_execution_id);
CREATE INDEX IF NOT EXISTS idx_restore_executions_status
    ON restore_executions (status, created_at DESC);
