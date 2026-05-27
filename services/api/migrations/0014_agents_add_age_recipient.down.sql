-- 0014_agents_add_age_recipient.down.sql
DROP INDEX IF EXISTS idx_agents_age_recipient;
ALTER TABLE agents DROP COLUMN IF EXISTS age_recipient;
