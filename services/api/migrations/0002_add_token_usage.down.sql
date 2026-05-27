ALTER TABLE enrollment_tokens
  DROP COLUMN IF EXISTS max_uses,
  DROP COLUMN IF EXISTS uses_count,
  DROP COLUMN IF EXISTS revoked_at;