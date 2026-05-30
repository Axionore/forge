-- Slice B: Lightweight persistent pending dispatch queue for robust offline delivery
CREATE TABLE pending_dispatches (
    id UUID PRIMARY KEY,
    deployment_id UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    signed_job JSONB NOT NULL,           -- the full SignedJob ready to send
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_attempt_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_pending_dispatches_agent ON pending_dispatches (agent_id, created_at);
CREATE INDEX idx_pending_dispatches_deployment ON pending_dispatches (deployment_id);