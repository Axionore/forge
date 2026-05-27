-- Agents (nodes managed by Forge)
CREATE TABLE agents (
    id UUID PRIMARY KEY,
    hostname TEXT,
    public_key BYTEA NOT NULL UNIQUE,           -- Ed25519 public key for job verification
    agent_token_hash BYTEA,                     -- Hashed long-lived token for WS auth
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- One-time enrollment tokens
CREATE TABLE enrollment_tokens (
    token_hash BYTEA PRIMARY KEY,
    description TEXT,
    expires_at TIMESTAMPTZ,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT
);

-- WireGuard peers for mesh (one row per peer assignment)
CREATE TABLE wireguard_peers (
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    allowed_ips TEXT[] NOT NULL,
    endpoint TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, public_key)
);

CREATE INDEX idx_agents_public_key ON agents(public_key);
CREATE INDEX idx_enrollment_tokens_used ON enrollment_tokens(used_at);
