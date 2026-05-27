-- 0008_notifications.up.sql
-- Rich per-resource notifications for deployments, applications, agents, and system events.
-- Supports multiple channels with flexible config (secrets stored in JSONB; production encryption via KMS/age planned).
-- Event-driven from record_job_result, statistical canary analysis, system updates, etc.
-- Full delivery audit trail.

CREATE TABLE IF NOT EXISTS notification_channels (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    channel_type TEXT NOT NULL CHECK (channel_type IN ('email', 'discord', 'slack', 'telegram', 'webhook', 'pushover')),
    config JSONB NOT NULL DEFAULT '{}'::jsonb,  -- e.g. { "url": "...", "token": "...", "from": "..." } — encrypt at rest in production
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notification_channels_type_enabled ON notification_channels (channel_type, enabled);

CREATE TABLE IF NOT EXISTS notification_subscriptions (
    id UUID PRIMARY KEY,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('deployment', 'application', 'agent', 'system')),
    resource_id UUID,  -- nullable for 'system' global subscriptions
    channel_id UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    events JSONB NOT NULL DEFAULT '[]'::jsonb,  -- e.g. ["job_result.failed", "canary.promoted", "system.update.completed"]
    filters JSONB NOT NULL DEFAULT '{}'::jsonb, -- e.g. { "min_severity": "error", "job_types": ["deploy"] }
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notification_subscriptions_resource ON notification_subscriptions (resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_notification_subscriptions_channel ON notification_subscriptions (channel_id);

CREATE TABLE IF NOT EXISTS notification_deliveries (
    id UUID PRIMARY KEY,
    subscription_id UUID REFERENCES notification_subscriptions(id) ON DELETE SET NULL,
    channel_id UUID REFERENCES notification_channels(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    resource_type TEXT,
    resource_id UUID,
    payload JSONB,                    -- snapshot of the triggering context (job result, analysis blob, etc.)
    status TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'failed', 'skipped')),
    error TEXT,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_subscription ON notification_deliveries (subscription_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_channel ON notification_deliveries (channel_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_resource ON notification_deliveries (resource_type, resource_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_status ON notification_deliveries (status, created_at DESC);

-- Trigger to keep updated_at fresh (optional but consistent with other tables)
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_notification_channels_updated_at
    BEFORE UPDATE ON notification_channels
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_notification_subscriptions_updated_at
    BEFORE UPDATE ON notification_subscriptions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
