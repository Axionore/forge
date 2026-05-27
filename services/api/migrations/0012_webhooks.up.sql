-- 0012_webhooks.up.sql
-- Tier 3-1: Universal webhook endpoints (beyond git-specific)
-- Generic, secure inbound webhooks that any external system can call to trigger
-- real deployments through the existing engine (catalog or existing deployment base).
-- Secrets stored in plaintext for v1 (see tier3-2 for envelope/KMS migration).
-- Deliveries are fully audited for observability and debugging.

CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    secret TEXT NOT NULL,                    -- high-entropy value generated on creation; callers use it for HMAC
    action_type TEXT NOT NULL CHECK (action_type IN ('deploy_catalog', 'deploy_deployment')),
    action_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Example action_config:
    --   {"catalog_key": "node-buildpack", "application_id": "...", "variables": {"TAG": "v1.2.3"}}
    --   or {"base_deployment_id": "...", "application_id": "..."}
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_enabled ON webhook_endpoints (enabled);
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_created ON webhook_endpoints (created_at DESC);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY,
    webhook_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL CHECK (status IN ('success', 'failed', 'signature_failed')),
    status_code INTEGER,
    duration_ms INTEGER,
    payload_sha256 TEXT,                     -- first 16 bytes of sha256 of the raw body for correlation without storing PII
    error_message TEXT,
    response_body TEXT
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_time ON webhook_deliveries (webhook_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries (status, received_at DESC);
