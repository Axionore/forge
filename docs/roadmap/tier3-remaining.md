# Remaining Tier 3 Items (Post-Secrets + SSH)

The core of Tier 3 (advanced secret management + SSH key generation/storage + wiring into Git/builds) is complete.

## 1. Structured logs, traces, and enhanced metrics
- Extend existing `JobResultDetails` and deployment_metrics with structured events for secret access, SSH key usage, and build steps.
- Add OpenTelemetry spans around checkout, secret decryption, and container start (using existing tracing).
- UI: Enhance the existing metrics dashboard with secret/SSH events.
- Next concrete step: Add a `SecretEvent` variant in JobResultDetails and emit it from execution.rs on successful SSH checkout and secret injection.

## 2. RBAC + real OIDC
- Move beyond single admin token.
- Add projects/teams, roles (viewer/deployer/admin).
- Integrate OIDC (e.g., via openidconnect crate or proxy).
- Enforce on all /admin and sensitive routes.
- Keep simple token for air-gapped bootstrap.
- Architecture note: Use the existing agent identity + new user sessions table. Middleware for claims.

## 3. Cost analytics / chargeback
- Leverage existing container stats + deployment_metrics.
- Add resource accounting (CPU/mem-seconds, network) per deployment/project.
- Simple in-memory or DB rollups + /admin/costs endpoint.
- UI dashboard extension.
- Next: Add cost attribution labels and a background rollup in the API.

## 4. Edge, CDN & smart blue-green
- Warm pools: Pre-provision "ready" containers for popular images.
- Predictive scaling: Simple heuristics on metrics (p99, error rate) to adjust replicas before canary.
- CDN hints: Add Cache-Control / edge labels in Traefik config generation.
- Smarter blue-green: Traffic mirroring + automated cutover based on real metrics (builds on existing xDS + canary analysis).
- All must still go through the statistical + xDS engine.

## SSH Keys Polish (done in this slice)
- Generation + encrypted storage via secrets system.
- Association with git_sources.
- Agent-side checkout using injected key + GIT_SSH_COMMAND (wired in execution.rs).
- UI guidance in Git Sources dialog.

All future work must continue to use the minimal-trust model, age secrets, and the same dispatch/strategy/xDS paths.