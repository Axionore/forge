-- Store full JobResults received from agents for observability and debugging.
-- Linked to deployments when correlation_id matches a deployment.

CREATE TABLE job_results (
    id UUID PRIMARY KEY,
    deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    job_type TEXT NOT NULL,
    correlation_id TEXT,
    success BOOLEAN NOT NULL,
    error TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    details JSONB,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_job_results_deployment ON job_results(deployment_id);
CREATE INDEX idx_job_results_agent ON job_results(agent_id, received_at DESC);
CREATE INDEX idx_job_results_correlation ON job_results(correlation_id);