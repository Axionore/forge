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
> `cargo test --workspace` green.
>
> **Update 2026-06-02 — 🟠 A01 per-action RBAC RESOLVED.** The authenticated principal now flows
> from the auth layer into every per-action check; issued admin tokens are constrained by their
> roles and only the bootstrap `FORGE_ADMIN_TOKEN` is unrestricted. Verified:
> `cargo clippy --all-targets --workspace -- -D warnings` clean and `cargo test --workspace` green
> (126 tests; forge-api lib+bin includes the new rbac `db_tests` (3) and deployment
> `per_principal_rbac_tests` (7)). Mutation-checked (making `enforce` fail-open makes 3 deny-path
> tests fail). See the resolved sections below.

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

## ✅🟠 A01 — No per-action authorization (coarse single admin gate) — RESOLVED

All `/admin/*` routes sit behind one `require_admin_auth` middleware (constant-time bootstrap
check ✅). The per-action engine (`RbacService::principal_can` / `action_allowed`) existed but
handlers either never called it or — worse — called `enforce_action(None, …)` with a **hardcoded
`None`** (`require_cloud_provision`, `create_hetzner_server`, and the deployment/build/secret
gates). `None` is the bootstrap-superuser sentinel, so per-action RBAC was a **no-op for every
issued admin-token holder** (a HIGH fail-open: an operator token scoped to read-only could
provision cloud infra, rotate secrets, rollback/promote/redeploy any deployment — CWE-636).

**✅ Resolved (2026-06-02).** The authenticated principal now flows from the auth layer into every
per-action check:

1. **Auth resolves the principal.** `require_admin_auth` first constant-time-compares the presented
   `X-Admin-Token` against the bootstrap `FORGE_ADMIN_TOKEN` → principal `None` (unconstrained
   superuser). Otherwise it SHA-256 hashes the token and looks it up via
   `RbacService::lookup_principal_for_token`, which returns the `principal_id` only when the row
   exists, is **not revoked, and is not expired** — else a single enumeration-resistant `401`. Any
   DB/RBAC error fails closed (deny). The resolved `AuthPrincipal(Option<Uuid>)` is inserted into
   request extensions.
2. **Extractor.** `AuthPrincipal` implements `FromRequestParts`, reading the value from extensions;
   its absence (route reached without the middleware) fails closed to `401`.
3. **Enforcement with the real principal.** Every in-scope mutation now passes
   `principal.principal_id()` (never a hardcoded `None`): deployment create / rollback / promote /
   redeploy / preview-promote / preview-destroy / catalog-deploy (`deployments:write`); build
   trigger (`builds:create`, plus `secrets:use` when embedding named secrets); cloud provision —
   server/firewall/network/volume/load-balancer/ip/dns, resource list+delete, and the legacy
   Hetzner batch (`cloud:provision`); secret create / rotate / delete and SSH-key generate
   (`secrets:use`); application create (`applications:create`) and service create
   (`services:create`). Semantics: bootstrap `None` → allowed; a real principal → must hold the
   action via `action_allowed` (default-deny, fail-closed).
4. **Bootstrap is the only `None`.** Audited: no handler passes a hardcoded `None` to
   `enforce_action`/the provisioning `principal_id` argument; the sole `None` is the genuine
   bootstrap path produced by the constant-time match in `require_admin_auth`.

A new `POST /admin/principals/{id}/roles` grant endpoint (`RbacService::assign_role`) makes the
model usable — without it an issued token's principal would hold no roles and be denied everything.

Tests: `rbac::db_tests` (`#[sqlx::test]`) prove a valid token resolves to its principal while
unknown / revoked / expired tokens resolve to nobody, and `principal_can` is default-deny through
real roles. `deployment::per_principal_rbac_tests` (`#[sqlx::test]`) prove a principal **without**
`cloud:provision` / `deployments:write` / `secrets:use` (and `applications:create` /
`builds:create`) is rejected `Forbidden` on the corresponding mutation, the bootstrap path (`None`)
is allowed, and a principal holding the grant is allowed. Mutation-checked: making `enforce`
fail-open (`Ok(_) => Ok(())`) makes the three deny-path tests fail; reverted. No migration was
required (the 0015 RBAC schema already carries `admin_tokens.principal_id` + `expires_at` +
`revoked_at`); `.sqlx` regenerated for the new queries.

## ✅🔴 A01 — IDOR / cross-tenant build-secret access (source-to-deploy) — RESOLVED

`trigger_build` (`main.rs`) resolved build secrets by NAME only
(`get_build_secret_ref(name)`), so a build for application A could reference ANY secret in the
instance by name — cross-application/cross-tenant disclosure of an age-encrypted secret into a
`BuildSpec`.

**✅ Resolved (2026-06-02).** Secret resolution is now application-scoped. The `secrets` table
already carries `application_id` (migration 0013, nullable), so the scoping model is:
_a secret resolves for a build iff it is owned by the build's application (`application_id = $app`)
or is an explicitly instance-global secret (`application_id IS NULL`)_; an app-owned secret wins
over a same-named global one (`ORDER BY application_id NULLS LAST`). `get_build_secret_ref` now
takes `application_id` and filters `WHERE name=$1 AND enabled=true AND (application_id=$2 OR
application_id IS NULL)`. `trigger_build` passes the build's `app_id`; a requested name that does
not resolve in scope is rejected (`400 unknown build secret`) — fail closed, never silently
skipped. Embedding any secret into a `BuildSpec` is additionally gated on the `secrets:use`
per-action RBAC permission via `enforce_action` (default-deny; `None` principal = authenticated
bootstrap admin, consistent with `create_build`). No new migration was required.
Test: `deployment::build_pipeline_tests::build_secret_resolution_is_application_scoped`
(`#[sqlx::test]`) proves app A cannot resolve app B's same-named or B-only secret, that an
in-scope secret and an explicitly-global secret both resolve, and that unknown names resolve for
nobody. Mutation-checked (dropping the `application_id` filter makes the test fail).

## ✅🔴 A05/EoP — git remote-helper / argument-injection smuggling at clone time — RESOLVED

`is_safe_git_token` (`crates/agent/src/build.rs`) was a metacharacter _blocklist_. A URL such as
`ext::sh -c <cmd>` (a git remote helper) or `transport::`/`file://` transport tricks could smuggle
command execution at clone time — the Coolify Jan-2026 RCE class — without tripping any blocked
character.

**✅ Resolved (2026-06-02).** Defense in depth, two independent layers:

1. **Structural URL validation** — new `validate_git_url` requires `src.url` to parse via the
   `url` crate as an absolute URL whose scheme is on a strict allowlist `{https, ssh, git}`;
   rejects embedded whitespace/quotes, control chars, leading `-`, and host-less URLs. `ext::`,
   `transport::`, `file://`, `http://`, and relative/bare refs are all rejected. Called _before_
   the existing metacharacter blocklist in `validate_source`.
2. **Transport hardening on every git invocation** — `run_git` now prepends
   `-c protocol.ext.allow=never -c protocol.file.allow=never -c protocol.allow=user` and sets
   `GIT_ALLOW_PROTOCOL=https:ssh:git`, so even a validation bypass cannot invoke a remote helper or
   local transport (including indirect transports via redirects/submodules).
   Tests (`crates/agent/src/build.rs`): `validate_git_url_accepts_real_remotes`,
   `validate_git_url_rejects_remote_helper_and_transport_smuggling` (covers `ext::`, `transport::`,
   `file://`, `http://`, relative, `-`-prefixed, whitespace, oversized), and
   `git_args_carry_protocol_restrictions` (asserts the config flags precede the subcommand and the
   original argv is preserved). Mutation-checked (adding `http` to the scheme allowlist makes the
   rejection test fail). `url` was promoted from a transitive to a direct dependency of `forge-agent`
   (no new code in the supply chain — already resolved at v2.5.8 in `Cargo.lock`).

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
