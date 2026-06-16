-- 0021_build_provenance.down.sql
ALTER TABLE builds
    DROP COLUMN IF EXISTS signed,
    DROP COLUMN IF EXISTS provenance,
    DROP COLUMN IF EXISTS supply_chain_policy;
