-- 0015_rbac.up.sql
-- Tier 3-4: Full additive RBAC scaffolding for admin operators and future multi-tenant.
-- Principals represent human operators or API keys that can act on /admin surfaces.
-- Bootstrap FORGE_ADMIN_TOKEN (env) is always treated as implicit full "admin" (fast constant-time path, never stored in DB).
-- Issued admin_tokens are hashed (sha256 BYTEA PK, raw returned exactly once) and linked to a principal + one or more roles.
-- Roles carry flexible JSONB permissions (e.g. {"*": true}, {"deployments:*": true, "secrets:read": true}).
-- Default-deny everywhere (OWASP A01 #1, ASVS L2 V8 Authorization). All checks server-side only.
-- Projects + teams tables included as additive scaffolding for roadmap (principal scoping, team membership) — enforcement in later slices.
-- Audit columns + soft deletes on mutable entities for compliance (A09). Fail-closed on every path.
-- All queries use parameterized sqlx (A05). Never log raw tokens or secrets (A09).

CREATE TABLE IF NOT EXISTS principals (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    principal_type TEXT NOT NULL CHECK (principal_type IN ('user', 'api_key')),  -- 'bootstrap' is implicit via FORGE_ADMIN_TOKEN only
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS admin_tokens (
    token_hash BYTEA PRIMARY KEY,
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    description TEXT,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '{}'::jsonb,  -- {"*":true} | {"deployments:*":true, "secrets:read":true} etc. Default-deny matcher in Rust.
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS principal_roles (
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by TEXT,
    PRIMARY KEY (principal_id, role_id)
);

-- Scaffolding for future project-scoped RBAC (roadmap item). No enforcement in v1 scaffolding.
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS teams (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS team_members (
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    role_in_team TEXT,  -- e.g. 'lead', 'member'
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, principal_id)
);

CREATE TABLE IF NOT EXISTS principal_projects (
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (principal_id, project_id)
);

-- Seed default roles (idempotent on re-run in dev)
INSERT INTO roles (id, name, description, permissions) VALUES
    (gen_random_uuid(), 'viewer', 'Read-only access to deployments, agents, secrets, git sources', '{"deployments:read": true, "agents:read": true, "secrets:read": true, "git-sources:read": true}'),
    (gen_random_uuid(), 'operator', 'Full deploy/git/secret-read + limited write', '{"deployments:*": true, "agents:read": true, "secrets:read": true, "git-sources:write": true, "webhooks:write": true, "backups:*": true}'),
    (gen_random_uuid(), 'admin', 'Full access (bootstrap equivalent for issued tokens)', '{"*": true}')
ON CONFLICT (name) DO NOTHING;

-- Performance indexes (principal lookup is hot path for issued-token auth)
CREATE INDEX IF NOT EXISTS idx_admin_tokens_principal ON admin_tokens (principal_id);
CREATE INDEX IF NOT EXISTS idx_principal_roles_principal ON principal_roles (principal_id);
CREATE INDEX IF NOT EXISTS idx_principals_deleted ON principals (deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles (name) WHERE revoked_at IS NULL;