-- Persistent time-series for heartbeats, healthchecks, container stats, and rollout progress
CREATE TABLE IF NOT EXISTS deployment_metrics (
    id BIGSERIAL PRIMARY KEY,
    deployment_id UUID REFERENCES deployments(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    metric_name TEXT NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    labels JSONB DEFAULT '{}'::jsonb,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_deployment_metrics_deployment_time ON deployment_metrics (deployment_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_deployment_metrics_name ON deployment_metrics (metric_name, timestamp DESC);