-- 0014_agents_add_age_recipient.up.sql
-- Tier 3-2: Store the public age recipient for each agent so the control plane
-- can encrypt secrets that only that agent (or set of agents) can decrypt.
-- This is public material only (the "age1..." string).

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS age_recipient TEXT;

CREATE INDEX IF NOT EXISTS idx_agents_age_recipient ON agents (age_recipient) WHERE age_recipient IS NOT NULL;
