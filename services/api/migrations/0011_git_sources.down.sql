-- 0011_git_sources.down.sql
ALTER TABLE deployments
    DROP COLUMN IF EXISTS git_source_id,
    DROP COLUMN IF EXISTS commit_sha,
    DROP COLUMN IF EXISTS ref;

DROP TABLE IF EXISTS git_sources;
