-- 0024_backup_restore_s3.down.sql
DROP TABLE IF EXISTS restore_executions;

ALTER TABLE backup_schedules
    DROP COLUMN IF EXISTS target_container,
    DROP COLUMN IF EXISTS retention_count,
    DROP COLUMN IF EXISTS s3_secret_id,
    DROP COLUMN IF EXISTS s3_access_key_id,
    DROP COLUMN IF EXISTS s3_region;
