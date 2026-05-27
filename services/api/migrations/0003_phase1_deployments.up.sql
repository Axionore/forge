-- Phase 1: Basic deployable applications and deployments
-- See docs/specs/phase-1-deploy-from-image.md

CREATE TABLE applications (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE deployments (
    id UUID PRIMARY KEY,
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    spec JSONB NOT NULL,                    -- serialized agent's DeploymentSpec
    status TEXT NOT NULL CHECK (status IN ('pending','in_progress','healthy','unhealthy','failed','rolled_back')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (application_id, version)
);

CREATE TABLE deployment_targets (
    deployment_id UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    replicas INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (deployment_id, agent_id)
);

-- Simple registry credentials for Phase 1 (encrypted at rest later)
CREATE TABLE registry_credentials (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    registry_host TEXT NOT NULL,
    username TEXT,
    password_encrypted BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_deployments_app ON deployments (application_id, version DESC);
CREATE INDEX idx_deployment_targets_agent ON deployment_targets (agent_id);
CREATE INDEX idx_applications_name ON applications (name);
