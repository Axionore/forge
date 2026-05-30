# Forge control-plane security review — 2026-05-30

Scope: `services/api` (control plane) security-sensitive surfaces, against OWASP Top 10:2025.
Trigger: Phase 2 rollback work + the user's "production-ready" gate. Read-only audit; findings
are prioritized with file:line and remediation. **No fixes applied** — several require the build
unblocked (see [[forge-build-prereqs]]) and one needs a key-management design decision.

Severity: 🔴 critical (blocks production) · 🟠 high · 🟡 medium · ✅ no finding.

## Verdict: NOT production-ready

Three 🔴 findings break the platform's core trust model (signed jobs + agent identity). They are
pre-existing (not introduced by the rollback change) but must be fixed before any GA claim.

> **Update 2026-05-30 — all three 🔴 findings RESOLVED.** See the per-finding "Resolved" notes
> below. Verified: `cargo clippy --all-targets --workspace -- -D warnings` clean and
> `cargo test --workspace` green (forge-api suite: rbac 4 + rollback 4 + webhook 7 + enrollment 2 =
> 17 tests, plus forge-agent 4 — 0 failures). The 🟠 A01 per-action RBAC item remains open.

---

## ✅🔴 A08/A04 — Control-plane signing key is ephemeral AND duplicated (job-integrity broken) — RESOLVED

- `services/api/src/main.rs:183` — `state.signing_key = SigningKey::generate(OsRng)` (fresh per process).
- `services/api/src/enrollment.rs:117` — `EnrollmentService` generates a **second, independent**
  `SigningKey::generate(OsRng)` and returns _its_ verifying key to agents as `control_plane_public_key`.

Jobs are signed with `state.signing_key`, but agents are handed the _enrollment service's_ public
key at enrollment → **agents can never verify the signatures of the jobs they receive** (key
mismatch), and every CP restart rotates both keys → all prior enrollments break. This silently
defeats the Ed25519 signed-job model that is Forge's headline security guarantee.

**Fix:** one signing key, loaded from a secret store (env/file/KMS — a design decision), shared by
the API and `EnrollmentService` (inject the same `Arc<SigningKey>` into `EnrollmentService::new`).
Persist it so it survives restarts. Add a test that an enrolled agent's stored CP pubkey verifies a
job signed by the live key.

**✅ Resolved (2026-05-30).** `main.rs::load_or_create_signing_key` now resolves ONE key in priority
order: (1) `FORGE_CP_SIGNING_KEY` (base64 32-byte ed25519 seed, from a secret manager/KMS), else
(2) a persisted seed at `$FORGE_STATE_DIR/cp-signing-key` (default `/var/lib/forge/cp-signing-key`),
created `0600` if absent with a loud warning that an ephemeral-on-disk key was generated. The seed is
never logged (only the public key is). The same `Arc<SigningKey>` is injected into both `AppState` and
`EnrollmentService::new(pool, key)`; `EnrollmentResponse.control_plane_public_key` is now that key's
`verifying_key()`. Test `enrollment::enrollment_tests::returned_pubkey_verifies_jobs_signed_by_live_key`
proves a job signed by the live key verifies against the enrollment-returned pubkey (and that an
unrelated key does not).

## ✅🔴 A07/A04 — Agent tokens are predictable and never persisted — RESOLVED

- `services/api/src/enrollment.rs:198` — `let agent_token = format!("agent-{}", agent_id);` — the
  long-lived WS auth token is just `"agent-" + <enrollment-returned UUID>` → **guessable**, not
  high-entropy.
- The enrollment flow never writes `agents.agent_token_hash`, yet `agent_ws.rs` authenticates with
  `WHERE agent_token_hash = $1`. So WS auth either always fails or (worse, if a fallback exists)
  accepts a predictable token.

**Fix:** generate a CSPRNG token (≥256-bit, e.g. `generate_secure_token(32)` already used in
`rbac.rs:290`), store only its SHA-256 in `agents.agent_token_hash` during enrollment, return the
raw value once. Constant-time compare on WS auth.

**✅ Resolved (2026-05-30).** `enrollment.rs::enroll` now issues `generate_secure_token(32)` (256-bit
CSPRNG, URL-safe base64), persists only `sha2::Sha256` of it into `agents.agent_token_hash` in the
`INSERT INTO agents`, and returns the raw token exactly once in `EnrollmentResponse.agent_token`. The
guessable `agent-<id>` form is gone. `agent_ws.rs` WS auth already hashes the presented token and looks
it up by `agent_token_hash` (an attacker must produce a preimage of a stored SHA-256). Test
`enrollment::enrollment_tests::token_is_random_hashed_and_authenticates` proves the round-trip: token
is not `agent-`-prefixed, the stored hash equals SHA-256(raw token), and a different token does not
match.

## ✅🔴 A08 — Git webhook signature check is non-cryptographic and fails open — RESOLVED

- `services/api/src/deployment.rs:~2112` (`handle_git_webhook`) — validation is
  `sig_clean.contains(secret) || sig_clean.ends_with(secret)` with a comment "Do not hard fail in
  v1" → **any attacker who knows/guesses the secret substring, or sends no signature, gets a
  deployment created** (CWE-345, fail-open).

**Fix:** compute HMAC-SHA256 over the raw body with the stored secret and `ring::hmac::verify`
(constant-time); reject (401) on mismatch or missing signature. Validate against the **raw** request
body, not parsed JSON.

**✅ Resolved (2026-05-30).** `git_webhook_handler` now takes `axum::body::Bytes` (raw wire bytes) and
threads them into `handle_git_webhook`, which calls `verify_git_webhook_signature` BEFORE any work.
GitHub (`X-Hub-Signature-256: sha256=<hex>`) is verified via `ring::hmac::verify` (constant-time)
HMAC-SHA256 over the raw body; GitLab (`X-Gitlab-Token`) is a constant-time shared-secret compare. It
**fails closed**: missing/invalid signature with a configured secret returns `DeploymentError::Unauthorized`
→ HTTP 401. Sources with no secret are accepted only with an explicit audit warning (dev-only). Tests
in `deployment::webhook_signature_tests` cover valid HMAC pass, tampered body, wrong secret, missing
signature, malformed hex, GitLab match/mismatch, and an end-to-end `handle_git_webhook` fail-closed
check against real Postgres.

---

## 🟠 A01 — No per-action authorization (coarse single admin gate)

All `/admin/*` routes sit behind one `require_admin_auth` middleware
(`main.rs:388-391`, constant-time check at `main.rs:563` ✅). But there is **no per-action RBAC**:
`RbacService::principal_can` / `action_allowed` (`rbac.rs:410-448`) exist and are **never called**
from handlers. Any holder of any admin token can rollback/promote/redeploy/delete **any** deployment
(no ownership/tenant scoping). Acceptable only for a single-operator deployment; a production
multi-user posture needs least-privilege.

**Fix (post-0016):** thread `RbacService` into the deployment handlers and gate state-changing
actions (`deployments:write`, etc.) via `action_allowed`; default-deny. (Note: `DeploymentService::new`
currently takes only `pool` while `main.rs:196` tries to pass an rbac service — part of the 0016
breakage to reconcile.)

## ✅ Cleared

- **A01 (rollback endpoints):** `/deployments/{id}/{rollback,promote,redeploy}` and create are inside
  the authenticated `admin_routes` group (`main.rs:359-361, 252`) — no regression from this change.
- **A04 (admin token):** bootstrap token constant-time compared (`ring::constant_time`,
  `main.rs:563`); issued tokens SHA-256 hashed in DB (`rbac.rs:291`).
- **A05 (injection):** all DB access is parameterized via sqlx `query!`/`bind` — no string-built SQL.
- **A09 (logging):** no tokens/secrets/passwords logged; failures log generic messages.
- **A10/A02 (errors):** `ApiError::Internal` returns no detail (`main.rs:788-793`); sqlx errors are
  wrapped, not echoed. (Minor 🟡: `"Invalid DeploymentSpec: {e}"` echoes serde detail — low risk.)

## Not yet reviewable

`A03` (supply chain / `cargo audit`), runtime `A02` (headers/CORS/TLS config), and a full re-review
of the 0016 Services/RBAC surface require the crate to compile + `cargo`/audit tooling to run — see
[[forge-build-prereqs]]. Re-run `owasp-auditor` after the build is green.

---

### Remediation order

1. ✅ Single persisted signing key shared API↔Enrollment (🔴, unblocks the trust model).
2. ✅ CSPRNG + hashed agent token, persisted on enrollment (🔴).
3. ✅ HMAC-SHA256 constant-time webhook verification, fail closed (🔴).
4. Per-action RBAC on mutating handlers (🟠, after 0016 lands). — still open.
