-- 0020_builds.up.sql
-- Phase B (source-to-deploy): persisted build records.
-- A build fetches a pinned commit from a git source, runs a builder (dockerfile/nixpacks/
-- compose/buildpack-scaffold) on an agent in a sandbox, and produces a container image.
-- On success the control plane dispatches a Deploy using the produced image; a FAILED build
-- never deploys (fail-closed, OWASP A10).
--
-- Security:
-- - No secret material in this table. Build secrets travel as age envelopes in the signed
--   Build job's spec, decrypted only on the agent to tmpfs (threat-model Information disclosure).
-- - created_by_principal_id ties the build to the actor for the auditable commit→image→deploy
--   chain (Repudiation mitigation). RBAC `builds:create` (default-deny) gates creation.
-- - Parameterized writes only (A03). error is a sanitized string (never secrets/host paths, A09).
-- uuid7 PK for time-ordered, index-friendly IDs (Postgres 18 + existing convention).

CREATE TABLE IF NOT EXISTS builds (
    id UUID PRIMARY KEY,
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    git_source_id UUID REFERENCES git_sources(id) ON DELETE SET NULL,
    -- Pinned commit the build was fetched at (the source of truth for the artifact).
    commit_sha TEXT NOT NULL,
    -- Human-facing branch/tag the commit was resolved from.
    git_ref TEXT,
    -- Builder discriminant: 'dockerfile' | 'nixpacks' | 'compose' | 'buildpack'.
    builder TEXT NOT NULL CHECK (builder IN ('dockerfile', 'nixpacks', 'compose', 'buildpack')),
    -- Lifecycle: pending -> running -> succeeded | failed (or cancelled).
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')),
    -- Target image reference the build tags (name[:tag] or registry/name:tag).
    image TEXT,
    -- Image digest (sha256:...) recorded after a successful build.
    image_digest TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    -- Sanitized failure reason for the UI; never contains secrets or host paths (A09).
    error TEXT,
    created_by_principal_id UUID REFERENCES principals(id),
    -- Opaque reference to where streamed logs are retained (e.g. the build-log WS topic key).
    -- v1 streams logs live over the WS and persists the final result; full log archival is later.
    logs_ref TEXT,
    -- Deployment created from this build on success (the deploy side of the audit chain).
    deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_builds_application ON builds(application_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_builds_status ON builds(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_builds_commit ON builds(commit_sha);

COMMENT ON TABLE builds IS 'Phase B source-to-deploy build records. No secret material stored here; build secrets travel as age envelopes in the signed Build job. Fail-closed: a failed build never deploys.';
COMMENT ON COLUMN builds.commit_sha IS 'Pinned commit the artifact was built from — the root of the commit->image->deploy audit chain.';
COMMENT ON COLUMN builds.error IS 'Sanitized failure reason for UI. Never contains secrets, tokens, or host paths (OWASP A09).';
