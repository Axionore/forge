-- 0016_applications_foundation.up.sql
-- Phase 0: Core Application + Service domain models for Dokploy-parity UX (catalog, wizard, detail pages, light DB groundwork).
-- Additive on 0015_rbac (projects table already exists and is referenced; no changes to RBAC or agent tables).
-- Applications represent user-facing deployable units (Git, Dockerfile, Compose, Template, or catalog items).
-- Services represent managed resources (Postgres/Redis/etc. for Phase 1 light + Phase 3 full).
-- All specs (including secrets) use the existing age-encrypted path (deployment.spec.secrets or named secrets via encrypt_secret_for_recipients).
-- Never store plaintext secrets. All new surfaces must go through RbacService + action_allowed (default-deny) + principal attribution.
-- Audit columns + soft deletes for compliance (OWASP A09). RLS comments for future multi-tenant.
-- uuid7 for sortable IDs on high-churn tables (matches Postgres 18 + existing patterns).
-- All queries will be parameterized via sqlx (A05). Never log raw tokens/secrets/PII (A09).
-- Fail-closed everywhere. STRIDE considered for new authz + secret surfaces (see secure-sdlc + owasp-applied-baseline).

-- Additive extension of the existing applications table from 0003.
-- New columns for Phase 0/1 catalog + wizard + RBAC/audit + age secret specs.
-- Safe re-runnable in dev (down.sql drops the added columns conceptually via full table drop in practice).

ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS kind TEXT CHECK (kind IN ('git', 'dockerfile', 'compose', 'template', 'catalog')),
    ADD COLUMN IF NOT EXISTS spec JSONB DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'deploying', 'running', 'failed', 'stopped', 'deleting')),
    ADD COLUMN IF NOT EXISTS created_by_principal_id UUID REFERENCES principals(id),
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;

-- Backfill defaults for existing rows (dev only; prod would have explicit migration data step).
UPDATE applications SET kind = 'git' WHERE kind IS NULL;
UPDATE applications SET status = 'running' WHERE status IS NULL;
UPDATE applications SET spec = '{}'::jsonb WHERE spec IS NULL;
UPDATE applications SET metadata = '{}'::jsonb WHERE metadata IS NULL;

CREATE INDEX IF NOT EXISTS idx_applications_project ON applications(project_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_applications_created_by ON applications(created_by_principal_id);

CREATE INDEX IF NOT EXISTS idx_applications_project ON applications(project_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_applications_created_by ON applications(created_by_principal_id);

-- Light managed services (DBs, caches) for Phase 1 groundwork + Phase 3 one-click + backups.
-- Connection details and credentials delivered exclusively via existing age secret envelopes (never plaintext in this table).
CREATE TABLE IF NOT EXISTS services (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    application_id UUID REFERENCES applications(id) ON DELETE SET NULL,  -- optional owner app
    name TEXT NOT NULL,
    engine TEXT NOT NULL CHECK (engine IN ('postgres', 'mysql', 'mongo', 'redis', 'valkey', 'minio')),
    version TEXT,
    spec JSONB NOT NULL DEFAULT '{}'::jsonb,           -- image, env (age refs), volumes, resources
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'provisioning', 'running', 'failed', 'stopped', 'deleting')),
    connection_secret_id UUID,                         -- references existing secrets or deployment secrets; age-encrypted only
    backup_schedule JSONB,                             -- { "enabled": true, "cron": "...", "retention_days": 7, "s3_target": "..." } — Phase 3
    created_by_principal_id UUID REFERENCES principals(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_services_project ON services(project_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_services_application ON services(application_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_services_engine ON services(engine, status);

-- Minimal join for composition (app + its backing services). Can be denormalized later if hot.
CREATE TABLE IF NOT EXISTS application_services (
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    service_id UUID NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'primary',              -- primary, replica, cache, etc.
    attached_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (application_id, service_id)
);

-- Lightweight audit foundation (expanded in 1.6). Captures mutating actions on the new resources.
-- Full before/after + principal for compliance. No secret values ever stored here.
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    principal_id UUID REFERENCES principals(id),
    action TEXT NOT NULL,                              -- e.g. "applications:create", "services:provision", "secrets:rotate"
    resource_type TEXT NOT NULL,
    resource_id UUID,
    before JSONB,
    after JSONB,
    ip INET,
    user_agent TEXT,
    at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_principal ON audit_logs(principal_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action, at DESC);

-- RLS scaffolding (enable later when multi-tenant principals/projects are wired; for now comments + policy placeholders).
-- ALTER TABLE applications ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY applications_tenant ON applications USING (project_id IN (SELECT project_id FROM principal_projects WHERE principal_id = current_setting('app.current_principal')::uuid));

COMMENT ON TABLE applications IS 'Phase 0 foundation. All secret material in spec must be age-encrypted refs only (see deployment.spec.secrets and job.rs SecretRef). Access via RbacService.principal_can + action_allowed (default-deny).';
COMMENT ON COLUMN applications.spec IS 'Contains age-encrypted secret refs (never plaintext). Processed by agent execution.rs only after decrypt to tmpfs 0600.';
COMMENT ON TABLE services IS 'Light DB/service groundwork. connection_secret_id and spec secrets use existing age envelope path exclusively. One-time plaintext reveal only via amber UI banner.';
COMMENT ON TABLE audit_logs IS 'Minimal audit for Phase 0/1. Expand in 1.6. Never contains secret values or raw tokens (A09).';