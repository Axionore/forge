# STRIDE Threat Model — Source-to-Deploy (builds)

Feature: connect a Git repo → fetch by commit → build an image (Nixpacks / Dockerfile /
Compose) on the agent → sign + deploy. New attack surface: untrusted code execution (build),
external Git integration, build-time secret handling, image provenance. ASVS L2.

## Assets

- Agent host (Docker daemon, kernel) — builds run here.
- Control plane (Postgres, signing key, secrets, git/cloud tokens).
- Secrets (age-encrypted env/build secrets, registry creds, git tokens).
- Image artifacts + their provenance.

## Trust boundaries

1. Git repo content (UNTRUSTED) → build executor on the agent.
2. Webhook from Git provider (semi-trusted; HMAC-verified) → control plane.
3. Control plane → agent (signed jobs; existing root of trust).
4. Build output (image) → deploy/run (must be verified before run — Phase C).

## STRIDE

**Spoofing**

- Forged webhook → fake build/deploy. Mitigation: HMAC-SHA256 constant-time verify over raw body (done); reject unsigned. Build jobs are Ed25519-signed like all jobs.
- Impersonating the control-plane registry. Mitigation: registry creds age-encrypted; pinned registry host.

**Tampering**

- Malicious repo alters build to exfiltrate/implant. Mitigation: build runs in an isolated Docker build context on the agent only; inputs pinned by commit SHA (no floating refs at build time); image digest recorded; Phase C signs + attests so tampered images fail verification before run.
- Poisoned base image / dependency. Mitigation: record digests; (Phase C) provenance; future: pin base images.

**Repudiation**

- "I didn't deploy that." Mitigation: audit_logs records principal → commit SHA → image digest → target (0016 audit table); build records persisted.

**Information disclosure**

- Build secrets baked into image layers. Mitigation: secrets injected via BuildKit `--secret` / age-decrypted to tmpfs 0600, NEVER as ARG/ENV that persists; `docker history` clean. Git/cloud tokens never logged; build logs scrubbed of known secret values.
- Build logs leaking env. Mitigation: stream logs but redact known secret values; logs are admin-gated.

**Denial of service**

- Build bomb (infinite/huge build) exhausts the agent. Mitigation: per-build CPU/memory/disk/time limits (cgroup limits on the build container); concurrency cap per agent; build timeout → kill + fail-closed. Cap build context size.
- Malicious Compose with huge resource requests. Mitigation: validate/limit Compose resource fields; deploy strategy limits already exist.

**Elevation of privilege**

- Build escaping the container to root on the host (the Coolify Jan-2026 CVE class: command injection running repo data through host shell). Mitigation: NEVER interpolate repo content into a host shell on the control plane or agent; builds run via the Docker build API (bollard), not `sh -c "<repo data>"`; no `eval`. Run builds as non-root in the build container where possible; drop caps; no Docker socket exposure to the build itself.
- Compose requesting privileged/host-mount. Mitigation: deny `privileged`, host bind-mounts, and Docker-socket mounts in user Compose by default (allowlist + explicit opt-in behind a permission).

## Authorization (A01)

Every build/deploy endpoint behind admin auth + per-action RBAC (`builds:create`, default-deny). Git source + its token scoped to a project/principal.

## Fail-closed (A10)

Build failure → no deploy. Verification failure (Phase C signature/provenance) → refuse run. Partial build artifacts cleaned up. Timeouts everywhere.

## Test obligations (abuse-case-tester later)

Webhook without/with-bad HMAC rejected; build timeout enforced; secret not present in image layers (`docker history` / inspect); Compose with `privileged`/socket-mount rejected; oversized build context rejected; repo with shell metacharacters in name/branch cannot inject a host command.
