-- 0011_git_sources.up.sql
-- Git provider integrations for push-to-deploy and PR previews.
-- Supports GitHub App, GitLab, Bitbucket, Gitea, etc.
-- Secrets (tokens, webhook secrets) stored in JSONB; production encryption via KMS/age is planned.

CREATE TABLE IF NOT EXISTS git_sources (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('github', 'gitlab', 'bitbucket', 'gitea')),
    installation_id TEXT,                    -- For GitHub App installations, etc.
    config JSONB NOT NULL DEFAULT '{}'::jsonb,  -- { "webhook_secret": "...", "app_id": "...", "private_key": "..." (encrypted in prod) }
    access_token TEXT,                       -- Personal access token or OAuth (encrypt in prod)
    refresh_token TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,      -- repo list cache, permissions, etc.
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_git_sources_provider ON git_sources (provider);
CREATE INDEX IF NOT EXISTS idx_git_sources_enabled ON git_sources (enabled);

-- Optional: link deployments to a git source + commit for traceability
ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS git_source_id UUID REFERENCES git_sources(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS commit_sha TEXT,
    ADD COLUMN IF NOT EXISTS ref TEXT;       -- branch or tag

CREATE INDEX IF NOT EXISTS idx_deployments_git_source ON deployments (git_source_id);
