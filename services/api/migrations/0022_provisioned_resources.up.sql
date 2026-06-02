-- 0022_provisioned_resources.up.sql
-- Inventory of cloud infrastructure that Forge itself provisioned, so the control
-- plane can list, manage, and clean up what it created. One row per created resource
-- (server, firewall, network, volume, load_balancer, ip, dns_record).
--
-- `external_id` is the provider-scoped identifier (Hetzner numeric ID stringified,
-- AWS/GCP string IDs, DNS record IDs, etc). `metadata` carries non-secret, provider-
-- specific detail (IPs, sizes, leftover IDs from a partial failure). No token or other
-- secret material is ever stored here.

CREATE TABLE IF NOT EXISTS provisioned_resources (
    id UUID PRIMARY KEY,
    provider TEXT NOT NULL,                 -- "hetzner", "aws", ...
    kind TEXT NOT NULL,                     -- server|firewall|network|volume|load_balancer|ip|dns_record
    external_id TEXT,                       -- provider-scoped ID (null only while a create is in flight)
    name TEXT,
    region TEXT,
    status TEXT NOT NULL DEFAULT 'active',  -- active|partial|deleting|deleted|error
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    application_id UUID REFERENCES applications(id) ON DELETE SET NULL,
    created_by_principal_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT provisioned_resources_kind_check CHECK (
        kind IN ('server', 'firewall', 'network', 'volume', 'load_balancer', 'ip', 'dns_record')
    ),
    CONSTRAINT provisioned_resources_status_check CHECK (
        status IN ('active', 'partial', 'deleting', 'deleted', 'error')
    )
);

-- Primary lookup pattern: "what did <provider> create of <kind> [for <application>]".
CREATE INDEX IF NOT EXISTS idx_provisioned_resources_provider_kind_app
    ON provisioned_resources (provider, kind, application_id);

-- Listing live resources for a provider in the admin UI excludes soft-deleted rows.
CREATE INDEX IF NOT EXISTS idx_provisioned_resources_provider_live
    ON provisioned_resources (provider, created_at DESC)
    WHERE deleted_at IS NULL;
