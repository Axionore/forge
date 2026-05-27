-- 0008_notifications.down.sql
-- Reversible drop for notification system.

DROP TRIGGER IF EXISTS trg_notification_subscriptions_updated_at ON notification_subscriptions;
DROP TRIGGER IF EXISTS trg_notification_channels_updated_at ON notification_channels;

DROP FUNCTION IF EXISTS set_updated_at();

DROP TABLE IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS notification_subscriptions;
DROP TABLE IF EXISTS notification_channels;
