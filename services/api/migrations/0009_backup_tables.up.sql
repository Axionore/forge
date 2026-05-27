-- 0009_backup_tables.up.sql
-- First-class database and volume backups with scheduling and S3 support.
-- Complements the agent-side Job::Backup (pg_dump + optional S3 upload).
-- Integrates with the notification system (backup.success / backup.failed events).

CREATE TABLE IF NOT EXISTS backup_schedules (
    id UUID PRIMARY KEY,
    deployment_id UUID REFERENCES deployments(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    db_type TEXT NOT NULL,                    -- "postgres", "mysql", etc. (must match agent support)
    database_name TEXT,                       -- optional specific DB (null = all / default)
    schedule_type TEXT NOT NULL CHECK (schedule_type IN ('interval', 'cron')),
    schedule_value TEXT NOT NULL,             -- e.g. "86400" (seconds) or "0 2 * * *"
    retention_days INTEGER NOT NULL DEFAULT 30,
    s3_endpoint TEXT,
    s3_bucket TEXT,
    s3_key_prefix TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_backup_schedules_deployment ON backup_schedules (deployment_id);
CREATE INDEX IF NOT EXISTS idx_backup_schedules_enabled_next ON backup_schedules (enabled, last_run_at);

CREATE TABLE IF NOT EXISTS backup_executions (
    id UUID PRIMARY KEY,
    schedule_id UUID REFERENCES backup_schedules(id) ON DELETE SET NULL,
    deployment_id UUID REFERENCES deployments(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'success', 'failed', 'skipped')),
    db_type TEXT NOT NULL,
    size_bytes BIGINT,
    location TEXT,                            -- S3 key or volume path
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error TEXT,
    job_result_id UUID,                       -- link to the actual JobResult for full details
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_backup_executions_deployment ON backup_executions (deployment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_backup_executions_schedule ON backup_executions (schedule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_backup_executions_status ON backup_executions (status, created_at DESC);

-- Reuse the same updated_at trigger function from 0008 if it exists
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_backup_schedules_updated_at
    BEFORE UPDATE ON backup_schedules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
