-- 0009_backup_tables.down.sql
DROP TRIGGER IF EXISTS trg_backup_schedules_updated_at ON backup_schedules;
DROP TABLE IF EXISTS backup_executions;
DROP TABLE IF EXISTS backup_schedules;
