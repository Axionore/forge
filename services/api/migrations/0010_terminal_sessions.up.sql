-- 0010_terminal_sessions.up.sql
-- Audit and session management for interactive web terminals.
-- Every interactive shell session is tracked for security/compliance.

CREATE TABLE IF NOT EXISTS terminal_sessions (
    id UUID PRIMARY KEY,
    deployment_id UUID REFERENCES deployments(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    container_name TEXT NOT NULL,
    user_name TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    exit_code INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_terminal_sessions_deployment ON terminal_sessions (deployment_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_terminal_sessions_agent ON terminal_sessions (agent_id);
