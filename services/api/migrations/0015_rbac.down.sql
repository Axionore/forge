-- 0015_rbac.down.sql
-- Drops all RBAC scaffolding tables in reverse FK order. Safe for dev re-runs.
DROP TABLE IF EXISTS principal_projects;
DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS principal_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS admin_tokens;
DROP TABLE IF EXISTS principals;