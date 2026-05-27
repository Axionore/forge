-- 0013_secrets.up.sql
-- Tier 3-2: Secret store (advanced secret management)
-- Stores age-encrypted secret values (never plaintext at rest).
-- Supports scoping to projects/apps/deployments for least-privilege.
-- Audit-friendly with rotation tracking. Full redaction enforced in all API/UI paths.

CREATE TABLE IF NOT EXISTS secrets (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,

    -- Scope: which resources can reference this secret.
    -- For v1 we keep simple ownership; later we can add a secret_grants table.
    application_id UUID REFERENCES applications(id) ON DELETE CASCADE,
    -- deployment_id can be used for deployment-specific secrets (e.g. per-preview).
    deployment_id UUID REFERENCES deployments(id) ON DELETE CASCADE,

    -- The encrypted material. For the age-v1 baseline this is a JSONB
    -- representation of SecretCiphertext (version + recipient + payload).
    -- The actual plaintext never touches the DB or control plane logs.
    encrypted_blob JSONB NOT NULL,

    -- Metadata for rotation, ownership, and policy.
    rotation_policy JSONB,           -- e.g. {"max_age_days": 90, "notify_before_days": 14}
    last_rotated_at TIMESTAMPTZ,
    created_by TEXT,                 -- admin user or token prefix for audit

    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secrets_application ON secrets (application_id) WHERE application_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_secrets_deployment ON secrets (deployment_id) WHERE deployment_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets (name);

-- Optional: lightweight event log for secret access/rotation (can be extended later).
-- For v1 we rely on the general job_results + deployment_metrics for usage, plus
-- structured logs (never containing values) for access.
