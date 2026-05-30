# Forge Competitive Gap Analysis: Coolify, Dokploy, and Caddy (2026)

**Date**: June 2026  
**Audience**: Core team, stakeholders, and future contributors  
**Purpose**: Evidence-based comparison of Forge against the leading self-hosted deployment platforms. This document identifies where Forge already has structural advantages and where it must close gaps to become a credible threat.

---

## Executive Summary

**Coolify** is currently the category leader in self-hosted PaaS. It offers the broadest “it just works” experience (Git deploys, 280–360+ one-click services, previews, polished UI).

**Dokploy** is the strong lightweight challenger. It is frequently chosen for lower resource usage, stronger built-in monitoring/alerts/volume backups, and more advanced team/RBAC features.

**Caddy** is *not* a full PaaS competitor. It is a modern, simple reverse proxy/web server (excellent automatic HTTPS and readable configuration) that Coolify added as an alternative to its default Traefik. Many self-hosters prefer Caddy for simplicity in smaller or less dynamic stacks.

**Forge’s core differentiator** (already architected and partially executed):
- Minimal-trust execution model with a lightweight Rust agent on every node.
- The control plane never holds persistent SSH keys or Docker socket access.
- Ed25519-signed jobs with verification.
- Cryptographic enrollment + attestation hooks.
- Extremely deep, capability-rich Docker execution surface in the agent.
- Self-updates designed to use the *same* safe deployment engine (with tiered rollout).

This is a durable competitive wedge that Coolify and Dokploy cannot easily close without a major architectural rewrite.

**Current reality**: Coolify and Dokploy win on breadth, maturity, and time-to-first-deploy today. Forge can win on *trust, operational honesty under failure, zero-downtime reliability, and platform self-update safety* — the dimensions that matter most once teams run real production workloads.

---

## Competitor Overviews

### Coolify
- Mature, feature-rich self-hosted PaaS (Git + Docker image + Compose + Nixpacks/Railpack).
- Massive one-click template catalog (280–360+ services).
- SSH-based node management (the exact high-privilege model Forge was designed to replace).
- Traefik by default with Caddy support added later.
- Strong on previews, teams, backups, and monitoring.
- Higher resource consumption on the control plane.

### Dokploy
- Lightweight, production-oriented alternative to Coolify.
- Strong Git support, Docker/Compose, and multiple buildpack options.
- Excellent real-time monitoring, alerts, and S3 volume backups.
- Better emphasis on teams, organizations, and RBAC (some advanced features).
- Claims significantly lower resource footprint than Coolify.
- Heavy use of Docker Swarm for multi-node.

### Caddy
- Not a deployment platform — a modern Go-based web server and reverse proxy.
- Strengths: Extremely simple and readable `Caddyfile` configuration, automatic HTTPS, HTTP/3, low overhead.
- Frequently used in self-hosted Docker environments via `caddy-docker-proxy` (label-driven dynamic config, similar to Traefik).
- Coolify added first-class Caddy support as an alternative proxy.
- Many users prefer it over Traefik for smaller stacks due to lower cognitive load.

---

## Detailed Gap Analysis

| Dimension                        | Coolify                                      | Dokploy                                      | Caddy (as Proxy)                          | Forge (Current + Target)                                                                 | Gap / Opportunity for Forge |
|----------------------------------|----------------------------------------------|----------------------------------------------|-------------------------------------------|------------------------------------------------------------------------------------------|-------------------------------|
| **Security / Trust Model**      | High privilege: CP stores encrypted SSH keys + uses Docker socket/SSH on nodes | Similar SSH + Docker exposure model         | N/A                                      | **Major structural win**. Rust agent, no persistent root/SSH/socket from CP. Ed25519-signed jobs + verification. Attestation hooks. | This is Forge’s primary and hardest-to-copy advantage. |
| **Deployment Sources**          | Git (broad providers), Docker image, Dockerfile, Compose, Nixpacks/Railpack | Strong Git support + Docker/Compose + buildpacks | N/A                                      | Phase 1: Rich container image support (private registry, full `DeploymentSpec` with env, age secrets, ports, domains, healthchecks, resources, mounts, networks, canary weights). Git + builds planned for Phase 4. | Significant gap today. Completing Phase 1 image deploy is the critical bridge. |
| **One-Click Services / Templates** | 280–360+ (biggest strength)                 | Solid but smaller catalog                   | Can be deployed as a service (Forge already catalogs it) | None yet (catalog skeleton exists)                                                      | Coolify’s biggest moat for non-developer workloads. De-prioritize until core is solid. |
| **Zero-Downtime Strategies**    | Conditional and fragile on plain Docker (often falls back to stop-then-start for ports, PRs, consistent names). Good on Swarm. | Basic rolling                               | N/A                                      | **Target strength**. Health-gated rolling, blue-green, and canary with statistical analysis, traffic weights via labels, automatic rollback on defined thresholds. | High-leverage area. Coolify’s limitations are well-documented in production use. |
| **Observability**               | Logs + basic metrics and alerts             | Stronger (real-time metrics, alerts, AI log analysis, volume backups) | Basic logging                            | **Already competitive and in some areas leading**. Rich `JobResult` streaming, live WS logs (follow, filter, timestamps, download, copy), **Status Timelines** derived from real job results + rollout_state. | Continue expanding (Prometheus/OTel export, better alerting). |
| **Platform Self-Update Safety** | Improved but still privileged with high blast radius | Script/install-based                       | N/A                                      | **Designed from day 1 as first-class**. Uses the same deployment engine + tiered rollout (agents → stateless control plane → stateful) + graceful handover. | One of the strongest opportunities. “Updating Forge feels safer than updating Coolify” is a powerful claim. |
| **Networking / Ingress**        | Traefik (default, deep integration) + Caddy support | Typically Traefik                           | Simpler Caddyfile or `caddy-docker-proxy` labels | Agent generates **Traefik labels** (routers, services, canary weights). Native ACME support on control plane. | Opportunity: Add first-class Caddy support as an alternative ingress (leverages existing catalog entry). |
| **Multi-Server / Scaling**      | Multi-server via SSH, Swarm support         | Strong multi-server + Swarm emphasis        | Works with both                          | Agent-per-node model (architecturally superior for security and isolation). Multi-agent targets and strategies already present in Phase 1 UI. | Long-term advantage, but onboarding experience still maturing. |
| **Team / RBAC / Multi-tenancy** | Projects, teams, basic roles                | Stronger (organizations, advanced RBAC, SSO elements) | N/A                                   | Current: Admin token model. Full teams + RBAC planned for later phases. | Dokploy currently has an edge on enterprise team features. |
| **Resource Efficiency**         | Functional but can be heavier               | Marketed as significantly lighter           | Very lightweight                         | Rust agent is tiny by design. Control plane (Axum + Next.js) is also lightweight. | Easy, high-visibility win — publish benchmarks. |
| **Ease of Onboarding**          | Excellent one-command install + polished UI | Very polished one-command experience        | Extremely simple                         | Cryptographically strong enrollment, but still maturing. UI is advancing rapidly (Preview Spec modal, status timelines, enhanced logs dialog, private registry support). One-liner agent install is a known quick win. | Closing fast. |
| **Community & Maturity**        | Dominant (massive adoption, ~56k stars, active Discord) | Strong and rapidly growing (~34k stars)     | Excellent Go/web server ecosystem        | Very early stage. | Secondary priority until the product is usable for real workloads. |
| **API / Extensibility**         | Very good OpenAPI                           | Good                                        | Excellent (JSON API + plugins via xcaddy) | Axum API + signed jobs over WebSocket. Extremely rich `DeploymentSpec`. | Strong foundation. |

---

## Caddy-Specific Observations

- Caddy is already present in Forge’s service catalog (`services/api/catalog/caddy.json`) as a one-click “Caddy 2 Reverse Proxy” deployment.
- Forge’s agent currently only generates **Traefik labels** (including `forge.canary.weight` for traffic splitting).
- Coolify made Caddy a first-class, switchable proxy option. Many users who dislike Traefik’s label verbosity have migrated to Caddy + `caddy-docker-proxy`.
- **Opportunity**: Adding Caddy as a supported ingress option in Forge (Caddyfile generation or label compatibility) would be a relatively low-effort way to appeal to a vocal segment of the self-hosting community while still delivering Forge’s security and execution advantages.

---

## Strategic Recommendations

### Do Not Chase Feature Parity on Easy Things Yet
Coolify’s 280–360 templates, broad Git provider support, and PR preview environments are real strengths, but they are table stakes. Chasing them early risks turning Forge into “Coolify but written in Rust” and wastes the architectural advantages already built.

### Double Down on the Four “Threat Threshold” Claims
Forge becomes a credible alternative when sophisticated users can confidently say:
1. “Their security model is meaningfully better and I can actually verify it.”
2. “I can deploy real workloads with reliable zero-downtime and honest failure handling.”
3. “Updating the platform itself feels dramatically safer than updating Coolify or Dokploy.”
4. “The observability and debugging experience is clearly superior when things go wrong.”

### Near-Term Priorities (Aligned with Existing Roadmap)
1. **Complete Phase 1** (“I can actually deploy something real from a container image”) end-to-end, including polished UI, private registry support, and basic zero-downtime behavior.
2. Ship the “Update Forge” experience (Phase 3) as a showcase of the same safe engine.
3. Deliver the one-liner agent install script + excellent security positioning documentation with diagrams.
4. Consider adding Caddy as a first-class ingress alternative.
5. Use the recent work on **status timelines** and the **enhanced logs panel** heavily in demos — these already feel more production-grade than what the competitors currently surface.

### Suggested Positioning Language (Once Phase 1 Ships)
> “Coolify and Dokploy give you Heroku or Vercel on your own servers. Forge gives you the security model and operational honesty that serious cloud platforms use internally — running on your own servers.”

---

## References

- [docs/roadmap-competitive-advantage.md](./roadmap-competitive-advantage.md)
- [docs/coolify-gap-analysis-2026.md](./coolify-gap-analysis-2026.md) (deep code-level analysis of Coolify)
- Forge agent execution code (Traefik label generation and canary support)
- Public documentation and community discussions for Coolify and Dokploy (as of June 2026)

---

**This document should be treated as a living artifact.** It will be updated as Forge ships Phase 1, Phase 2 (zero-downtime), and Phase 3 (self-update), and as the competitors continue to evolve.

Last updated: June 2026