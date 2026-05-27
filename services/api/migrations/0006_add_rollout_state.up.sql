-- Rollout state for phased strategies (Rolling with health gates + auto-rollback)
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS rollout_state JSONB DEFAULT '{}'::jsonb;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS previous_spec JSONB;  -- snapshot for rollback

-- Index for active rollouts
CREATE INDEX IF NOT EXISTS idx_deployments_rollout_active ON deployments (status) WHERE status IN ('in_progress', 'unhealthy');