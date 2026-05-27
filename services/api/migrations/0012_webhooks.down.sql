-- 0012_webhooks.down.sql
-- Reversible drop for Tier 3-1 universal webhooks tables.

DROP INDEX IF EXISTS idx_webhook_deliveries_status;
DROP INDEX IF EXISTS idx_webhook_deliveries_webhook_time;
DROP TABLE IF EXISTS webhook_deliveries;

DROP INDEX IF EXISTS idx_webhook_endpoints_created;
DROP INDEX IF EXISTS idx_webhook_endpoints_enabled;
DROP TABLE IF EXISTS webhook_endpoints;
