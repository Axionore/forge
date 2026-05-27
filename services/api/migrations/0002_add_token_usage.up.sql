-- Extend enrollment_tokens for multi-use support and revocation (real token issuance)
ALTER TABLE enrollment_tokens
  ADD COLUMN IF NOT EXISTS max_uses INTEGER NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS uses_count INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- Helpful index for active token checks
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_active
  ON enrollment_tokens (revoked_at, used_at, expires_at, uses_count, max_uses);