-- 0016_applications_foundation.down.sql
-- Drops Phase 0 Application/Service foundation tables in reverse FK order. Safe for dev re-runs.
-- Does not touch 0015_rbac tables or any agent/enrollment/secret data.

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS application_services;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS applications;