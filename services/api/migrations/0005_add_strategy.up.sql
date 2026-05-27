-- Add strategy configuration to deployments for full zero-downtime strategies
ALTER TABLE deployments
ADD COLUMN strategy JSONB NOT NULL DEFAULT '{"type":"rolling","max_unavailable":1,"max_surge":1,"health_check_grace_period_secs":30,"rollback_on_failure":true,"failure_threshold":3}'::jsonb;

-- Backfill existing rows with default rolling strategy if needed
UPDATE deployments SET strategy = '{"type":"rolling","max_unavailable":1,"max_surge":1,"health_check_grace_period_secs":30,"rollback_on_failure":true,"failure_threshold":3}'::jsonb WHERE strategy IS NULL;