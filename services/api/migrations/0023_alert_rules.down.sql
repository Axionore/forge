-- 0023_alert_rules.down.sql
DROP TRIGGER IF EXISTS trg_alert_rules_updated_at ON alert_rules;
DROP TABLE IF EXISTS alert_events;
DROP TABLE IF EXISTS alert_rules;
