-- 0013_secrets.down.sql
DROP INDEX IF EXISTS idx_secrets_name;
DROP INDEX IF EXISTS idx_secrets_deployment;
DROP INDEX IF EXISTS idx_secrets_application;
DROP TABLE IF EXISTS secrets;
