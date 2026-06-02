-- 0021_build_provenance.up.sql
-- Phase C (supply-chain differentiator): record cosign signing + SLSA provenance on builds.
--
-- Extends the signed-job root of trust to BUILD ARTIFACTS. After a successful build the agent
-- cosign-signs the image BY DIGEST and attaches an in-toto/SLSA provenance attestation; before a
-- Forge-built image is run the agent cosign-verifies it (fail-closed). These columns persist the
-- verifiable chain principal -> commit -> image digest -> deployment alongside the existing
-- builds.image_digest + builds.deployment_id columns (0020).
--
-- Security:
-- - `provenance` is the NON-SECRET provenance summary (subject digest + source commit + builder).
--   It is a public attestation by design — safe to store and to surface in the UI / audit. NO key
--   material, tokens, or secrets are ever written here (OWASP A09).
-- - `signed` lets the control plane distinguish a supply-chain-complete build from one produced
--   under a `disabled`/`sign`-only policy.
-- - `supply_chain_policy` records the policy in force for this build for auditability. CHECK-
--   constrained to the three known values; an unknown value can never be persisted.
-- - All writes are parameterized via sqlx (A03).

ALTER TABLE builds
    ADD COLUMN IF NOT EXISTS signed BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS provenance JSONB,
    ADD COLUMN IF NOT EXISTS supply_chain_policy TEXT
        CHECK (supply_chain_policy IN ('disabled', 'sign', 'sign-and-require-verify'));

COMMENT ON COLUMN builds.signed IS 'Whether the produced image was cosign-signed + provenance-attested (Phase C). NO secret material.';
COMMENT ON COLUMN builds.provenance IS 'Non-secret SLSA provenance summary (subject digest + source commit + builder id). Public attestation — never secrets/tokens (OWASP A09).';
COMMENT ON COLUMN builds.supply_chain_policy IS 'Supply-chain policy in force for this build: disabled | sign | sign-and-require-verify.';
