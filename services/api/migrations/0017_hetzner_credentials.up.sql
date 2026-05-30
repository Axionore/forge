-- 0017_hetzner_credentials.up.sql
-- Persistent encrypted storage for Hetzner Cloud API credentials.
-- These are control-plane secrets (the CP must be able to decrypt them
-- to call the Hetzner API during provisioning).
--
-- Encrypted using age with a control-plane recipient (different from agent secrets).

CREATE TABLE IF NOT EXISTS hetzner_credentials (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,           -- e.g. "production", "staging-eu"
    description TEXT,

    -- age-encrypted token (JSONB matching SecretCiphertext shape for consistency)
    encrypted_token JSONB NOT NULL,

    -- Who created it (for audit)
    created_by TEXT,

    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hetzner_credentials_name ON hetzner_credentials (name);
CREATE INDEX IF NOT EXISTS idx_hetzner_credentials_enabled ON hetzner_credentials (enabled) WHERE enabled = true;