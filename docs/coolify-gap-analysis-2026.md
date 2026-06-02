# Coolify Gap Analysis — June 2026 (Updated)

**Source of truth**: Full Coolify v4 codebase vendored at `/home/iris/vendor/coolify` (Laravel 12 + Livewire 3 + Tailwind v4, ~360 service templates, 8.7k-line OpenAPI).

**Context**: This is a refreshed, evidence-based gap analysis for Forge roadmap prioritization. It builds on the May 2026 competitive assessment and incorporates direct code inspection of deployment logic, security model, provisioning, and operational surfaces.

---

## Executive Summary

Coolify remains the strongest open-source self-hosted PaaS in breadth and "it just works" polish for small-to-medium teams. It has closed several DX gaps (Railpack support, better PR redeploys, service secrets, improved update flow) since prior reviews.

**However, the fundamental architectural liabilities that make it unsuitable for security-conscious or high-stakes production use have not been addressed**:

- Persistent high-privilege SSH + Docker access from control plane to every node.
- Zero-downtime that is conditional and fragile on plain Docker (falls back to stop-then-start for PRs, host ports, consistent names).
- Self-update and platform operations that carry high blast radius.

These are not polish issues — they are structural. This is exactly the wedge Forge's minimal-trust Rust agent + signed job model is designed to exploit.

**Verdict**: Coolify wins on feature surface area and time-to-first-deploy today. Forge wins on the three things sophisticated users eventually care most about: *trust model*, *operational honesty under failure*, and *update safety*. The race is to make Forge's superior foundation deliver a complete "deploy real workloads" product before Coolify's momentum makes the security story irrelevant to most buyers.

---

## Coolify Strengths (What It Still Does Better)

| Area                        | Evidence from Codebase                                                                 | Why It Matters |
|-----------------------------|----------------------------------------------------------------------------------------|---------------|
| **One-click service breadth** | 360+ `templates/compose/*.yaml`; service templates JSON; on-demand SFTP for WordPress; VaultWarden, n8n, Ghost, MeiliSearch, etc. | Massive time-to-value for non-trivial stacks. Dokploy and early Forge lag here. |
| **Preview / PR deployments** | `ApplicationPreview`, `pull_request_id` handling, `addPreviewDeploymentSuffix` for volumes, redeploy PRs, dedicated branch tracking. See `tests/Unit/PreviewDeploymentBindMountTest.php` and deployment job. | Real review apps with isolated volumes. |
| **Git provider surface**    | GitHub App + manual webhooks for GitHub, GitLab, Bitbucket, Gitea. `manual_webhook_secret_*` fields. | Wider than most self-hosted alternatives. |
| **Build systems**           | Nixpacks, Railpack (new), Dockerfile (multi-location), Docker Compose, Static. Build server separation (`use_build_server`). | Flexible; Railpack addition shows responsiveness. |
| **Database + backup story** | Standalone* models for 8 engines; `ScheduledDatabaseBackup`; S3 + local targets; `DatabaseBackupJob`; notifications on success/failure/warning. | Production-grade for self-hosted DBs. |
| **Notifications & webhooks**| 7+ channels (Discord/Slack/Telegram/Pushover/Email/Webhook + transactional). Per-team defaults. | Better than Dokploy in breadth. |
| **Proxy & networking**      | Traefik fully managed per-server; automatic SSL; www/non-www redirects; custom domains. | Solves the hard part for most users. |
| **API**                     | Comprehensive OpenAPI 3.1 (8758 lines); Sanctum + ability-based auth (read/write/deploy). | Good for automation and future control planes. |
| **Team model**              | Owner/Admin/Member with rank comparison; policies on most resources; project/environment hierarchy. | Usable multi-tenancy for agencies/teams. |
| **Hetzner + provisioning UX**| Deep HetznerService integration; server validation jobs; private networks; cloud-init style bootstrap. | Best-in-class for the cheapest serious metal. |

Coolify's product velocity and template ecosystem are real moats for the 80% use case.

---

## Critical Gaps (Prioritized by Forge Leverage)

### 1. Security & Trust Model (Highest Leverage for Forge)

**The core problem remains unchanged**:

- Control plane stores (encrypted) SSH private keys (`PrivateKey` model, `casts['private_key'] => 'encrypted'`) and uses them persistently via SSH multiplexing (`SshMultiplexingHelper`) to execute arbitrary Docker commands on every managed server.
- Docker socket exposure patterns or root SSH mean full host compromise if the Coolify instance (or a team member with access) is breached.
- No node attestation, no short-lived credentials, no job signing/verification boundary between control plane and execution.

**Code evidence**:
- `app/Models/PrivateKey.php:45` (encrypted cast + filesystem sync)
- `app/Helpers/SshMultiplexingHelper.php` and `SshRetryHelper`
- `ExecuteRemoteCommand` trait used pervasively in deployment, server, proxy, and database actions
- No equivalent of Forge's Ed25519-signed jobs + verification layer

**Competitor reality**: Dokploy has similar SSH/Docker exposure. Railway/Render/Vercel keep execution inside their hardened control planes with strong isolation. None of the self-hosted options have solved the "control plane owns root on all your boxes" problem — this is Forge's opening.

**Impact**: Any serious compliance regime (SOC2, ISO27001, customer security questionnaires) eventually asks this question and Coolify fails it.

### 2. Zero-Downtime & Deployment Reliability

**Conditional and incomplete**:

From `ApplicationDeploymentJob.php:1878` (`rolling_update`):

```php
if (ports mapped || consistent container name || custom internal name || PR deployment || custom --ip) {
    // explicit log: "rolling update is not supported"
    stop_running_container(force: true);
    start_by_compose_file();
} else {
    start_by_compose_file();   // new version
    health_check();            // wait
    stop_running_container();  // old version
}
```

- Swarm gets real `docker stack deploy --detach` rolling.
- Everything else that matters for real apps (host ports for some reverse proxies, consistent names for certain clients, **all PR previews**) gets hard stop-then-start.
- Healthcheck logic exists and is reasonably thorough (`health_check_start_period`, retries, cmd vs URL), but the strategy engine above it is thin.
- No blue/green, no canary, no traffic-splitting weights, no automatic rollback on error-rate or health thresholds.

**Evidence**: Lines 1895-1922 and `health_check()` method (1930+). Backlog task exists for cleanup scheduling issues in cloud deploys.

**Competitor comparison**: Render and Railway make zero-downtime the default with health gates. Heroku dyno restarts are atomic at the router. Dokploy has similar limitations.

### 3. Platform Self-Update & Operational Safety

Coolify has improved the update story (new update process, version tags in unreleased changelog), but it still runs as a privileged process that can touch all resources it manages.

- No tiered rollout (agent vs control plane vs stateful).
- No pre-flight change preview that surfaces blast radius.
- No automatic rollback of the platform itself when an update bricks node connectivity.
- Cloud version still requires users to trust the hosted control plane with SSH keys to their servers.

Forge's Phase 3 goal (self-update as first-class magical experience reusing the same safe deployment engine) directly attacks a documented user pain.

### 4. Scalability & Architecture

- **No Kubernetes**. Swarm support exists (`SwarmDocker` destination) but Swarm adoption is low and Docker Inc. has de-emphasized it.
- Horizontal scaling for a single application on plain Docker requires user-managed replicas in compose or external orchestration. No first-class replica count + load balancing UI.
- Build fleet separation exists but is manual ("use build server").
- No automatic node draining, cordoning, or capacity-aware scheduling visible in the model.

For teams that outgrow a single powerful box + compose, the migration path is either "use Swarm" (declining) or "leave Coolify."

### 5. Observability & Debugging

- Container logs + basic server metrics (CPU/mem/disk trends) are present.
- No native Prometheus/OpenTelemetry export surface.
- No distributed request tracing hooks.
- No alerting beyond simple deploy success/failure and high disk usage notifications.
- Error messages during failed builds (especially multi-stage or private registry) remain developer-hostile in practice.

### 6. DX & Ecosystem Polish Gaps

- **Build caching**: Still an active backlog item (task-00001 series on BuildKit + registry caching for staging). Cold builds hurt iteration speed.
- RBAC is coarse (only 3 roles). No per-environment or per-resource ACLs, no deploy approval workflows.
- No GitOps / desired-state reconciliation loop that survives control-plane downtime (resources live on the servers, but drift detection is limited).
- Template ecosystem is wide but quality varies; no ratings, no verified publisher model, no easy "pin to digest" for supply-chain safety.
- Cloud offering is essentially "we run Coolify for you + support + HA control plane." No differentiated managed database, edge, or usage analytics layer that would justify premium over self-host + a good VPS.

### 7. Other Notable Gaps

- Secrets: "Service secrets" added, but still mostly environment variables + basic Docker secrets. No first-class integration with external secret stores (Vault, Doppler, 1Password, AWS Secrets Manager) for rotation/auditing.
- Audit / compliance: Activity exists in the DB but no exportable, tamper-evident audit log for security reviews.
- Multi-region / active-active: None.
- Cost attribution: Weak in both self-hosted and cloud.

---

## Quick Comparison Snapshot (2026)

| Dimension                  | Coolify                  | Dokploy             | Railway (self-host patterns) | Render / Vercel | Forge (target) |
|----------------------------|--------------------------|---------------------|------------------------------|-----------------|----------------|
| **Security model**        | SSH + Docker root       | Similar            | Cloud isolation             | Cloud isolation | Minimal-trust signed agent (win) |
| **Zero-downtime**         | Conditional (good on Swarm) | Basic             | Strong default              | Strong          | Health-gated strategies + rollback (target win) |
| **Self-update safety**    | Improved but privileged | Script-based       | N/A (managed)               | N/A             | Tiered + preview + rollback (target) |
| **Service templates**     | ~360 (strongest)        | Fewer              | Managed catalog             | Limited         | Parity later |
| **PR previews**           | Excellent               | Good               | Good                        | Excellent       | Parity |
| **K8s support**           | None                    | None               | None (they abstract)        | None            | Later (or never) |
| **API quality**           | Very good (OpenAPI)     | Good               | Excellent                   | Excellent       | Match |
| **Trust for compliance**  | Weak                    | Weak               | Strong (their problem)      | Strong          | Strong (our wedge) |

---

## Recommendations for Forge (Actionable)

1. **Do not chase template parity yet.** 80% of Coolify's perceived lead is 360 templates + nice GitHub App flow. Win the "I trust this in production and can update it without fear" narrative first (Phases 1-3). Templates are table stakes that can be added in parallel by contributors once the core is solid.

2. **Double down on the three Forge-unique proofs**:
   - Signed job + verification logs that a security reviewer can actually audit.
   - Zero-downtime + automatic rollback demo that survives real failure injection.
   - "Update Forge" flow that is visibly safer than Coolify's.

3. **Watch items in Coolify**:
   - Further investment in the new update process (if they make platform updates low-risk, it removes one wedge).
   - Any move toward short-lived node credentials or agent model (unlikely given Laravel/SSH architecture).
   - Docker Buildx/BuildKit caching landing — closes a real DX complaint.

4. **Positioning language** (use in docs/marketing once Phase 1 ships):
   > "Coolify and Dokploy give you Heroku on your own servers. Forge gives you the security and operational model that Heroku, Render, and Railway use internally — on your own servers."

---

## Appendix: Key Files Inspected

- `app/Jobs/ApplicationDeploymentJob.php` (rolling_update, health_check, fallback paths)
- `app/Models/PrivateKey.php` (encrypted storage + fs sync)
- `app/Enums/{BuildPackTypes,Role}.php`
- `templates/compose/` (360 files)
- `app/Notifications/Channels/` (7 delivery mechanisms)
- `openapi.yaml` (8758 LOC)
- Backlog tasks (build caching, Docker cleanup, UI simplification)
- `app/Services/HetznerService.php` (provisioning depth)

**Last refreshed**: June 2026 against current `vendor/coolify` tree.

This analysis is deliberately narrow and opinionated. The goal is not to list every missing checkbox — it is to surface the structural gaps that create durable competitive advantage for a security-first, minimal-trust alternative.
