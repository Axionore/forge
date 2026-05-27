ALTER TABLE deployments DROP COLUMN IF EXISTS rollout_state;
ALTER TABLE deployments DROP COLUMN IF EXISTS previous_spec;
DROP INDEX IF EXISTS idx_deployments_rollout_active;