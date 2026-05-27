# Forge Roadmap: From Promising Foundation to Real Competitive Threat

**Date**: 2026-06 (current state assessment)  
**Audience**: Core team + stakeholders  
**Goal**: Define the shortest path from "technically impressive agent + enrollment system" to "the deployment platform serious teams choose when they care about security, zero-downtime, and operational honesty."

## Current Position (Brutally Honest)

As of today, Forge has made **excellent** progress on the hardest parts of the original vision:

**Already differentiated / ahead of Coolify and Dokploy:**
- Minimal-trust execution model (Ed25519-signed jobs, no SSH keys or Docker socket exposure from control plane to nodes)
- Extremely deep Docker execution surface in the agent (far beyond what either competitor exposes)
- Cryptographic node identity + real enrollment flow (one-time tokens with multi-use support, revocation, WireGuard distribution hooks, attestation extension points)
- Structured observability primitives (rich `JobResult`, automatic periodic health with accurate container stats)
- Self-update architecture (ADR 0001 + graceful handover with real readiness signaling)

**Where we are weak or missing:**
- No complete "deploy my application" story that a normal developer can use today
- Control plane is almost entirely the enrollment surface
- Zero-downtime strategies, health gates, and rollback logic exist only as design intent
- No Git integration, builds, or source-to-deploy flow
- UI is a beautiful landing page + excellent token issuance tool — nothing else
- No one-liner experience, limited documentation, no demo environment

**Net result**: We have the best *engine* and *security foundation* of the three projects, but we are not yet a product anyone would choose over Coolify or Dokploy for actual work.

## The "Threat Threshold"

Forge becomes a credible threat when a technically sophisticated user or small team can say any of the following:

1. "Their security model is meaningfully better and I can actually use it."
2. "I can deploy a real application with proper zero-downtime and feel confident it won't take my service down during updates."
3. "Updating the platform itself feels safer than updating Coolify or Dokploy."
4. "The observability and debugging experience is clearly superior when things go wrong."

Everything else (one-click databases, 200 templates, AI commit messages, preview environments) is secondary until we clear these four bars. Chasing feature parity on the easy stuff before we win on the hard stuff is how we become another "also ran."

## Prioritized Roadmap

### Phase 0 — Current State (Security Root + Execution Engine)
**Status**: Mostly complete and high quality.

**What exists and is real**:
- Full Rust agent with maximized Docker execution
- Enrollment + admin token issuance (complete with DB, UI, multi-use, revocation)
- Signed jobs + verification
- Rich telemetry and WS bidirectional communication
- Self-update handover plumbing

**Next for this phase**: Minor hardening only (e.g. better error messages in enrollment, agent one-liner install script, improved docs for the security model). Do not spend significant cycles here until later phases are unblocked.

---

### Phase 1 — "I Can Actually Deploy Something" (Highest Priority)
**Why this phase creates threat**: Without this, everything else is academic. This is the minimum surface that lets someone evaluate Forge against Coolify/Dokploy with their own workload.

**Target outcome**: A developer can enroll a server, create an application from a public container image (or simple Dockerfile), set environment variables + domains, hit deploy, and have a working service behind Traefik with automatic SSL.

**Must-ship deliverables (no stubs)**:

1. **Core domain models** (`crates/core` or `crates/types`)
   - `Application`, `Deployment`, `DeploymentSpec` (reusing/extending the agent's excellent `DeploymentSpec` + `ContainerSpec`)
   - Source (initially just `ContainerImage`; Git comes in Phase 4)
   - Desired state vs actual state separation

2. **Control plane API surfaces** (Axum)
   - CRUD for Applications + Deployments
   - POST `/deployments/{id}/deploy` (or equivalent) that creates signed Jobs and sends them to the correct agent(s) via the existing WS receiver
   - Status polling + basic log tailing from agent `JobResult`s

3. **Minimal but excellent operator UI** (Next.js)
   - Applications list + detail
   - "New Deployment" form (image, env vars as key/value, port exposure, domain + Traefik labels)
   - Deploy button with clear progress + result
   - Live logs view (streaming from agent `ContainerLogs` + `Exec` jobs)
   - Status badges that reflect real agent-reported state (not optimistic only)

4. **Networking & Ingress (via agent)**
   - Automatic creation of required networks on the agent
   - Rich Traefik labels generated from the deployment spec (routers, services, TLS via Let's Encrypt)
   - Support for multiple domains + path-based routing

5. **Basic persistence & reconciliation**
   - Store desired state in Postgres
   - On agent reconnect/heartbeat, reconcile (at minimum detect drift and surface it)

**Success criteria (how we know it's real)**:
- End-to-end demo works on a fresh VPS: enroll → create app from `ghcr.io/...` image → set `PORT` + domain → deploy → visit URL and see the app.
- Deploying an updated image performs a rolling replacement (even if naive at first).
- Logs from the running container are visible in the UI within seconds.
- No "TODO" or "coming soon" in the critical paths.
- The experience feels more trustworthy than Coolify/Dokploy on the security dimension (agent never had root SSH).

**Anti-pattern to avoid**: Building a full Git build system in this phase. Image-based first is sufficient and dramatically faster to ship.

**Effort shape**: Large (biggest single phase). This is where most of the next 6–9 months should go.

---

### Phase 2 — Zero-Downtime That Actually Works
**Why this phase creates threat**: This is the #1 operational complaint about both Coolify and Dokploy in production use. Winning here is the fastest way to make sophisticated users say "these other tools feel amateur."

**Must-ship**:
- Strategy engine (start with `Rolling` + `BlueGreen`; Canary can come later)
- Health gate system that actually waits for real agent-reported health (using the existing rich health check job + container stats)
- Automatic rollback on defined failure thresholds (error rate, healthcheck failures, or explicit user thresholds)
- Per-deployment strategy configuration in the UI
- "Change preview" view before deploy (what will actually change on the agent)
- Honest communication when zero-downtime is not guaranteed (e.g. database schema changes)

**Reuse opportunity**: The agent's execution capabilities are already excellent. We mostly need orchestration + decision logic on the control plane + excellent UI for the strategy + rollback experience.

**Success criteria**:
- Deploying a new version with a proper healthcheck never drops traffic for end users (measured with real load).
- A deliberately broken deploy automatically rolls back and leaves the previous version healthy.
- The UI makes the strategy, health gates, and rollback policy extremely visible and understandable.

**Effort shape**: Medium-Large (builds directly on Phase 1).

---

### Phase 3 — "Update Forge" as a First-Class, Magical Experience
**Why this phase creates threat**: This directly attacks the documented pain point in both competitors. If we can make updating the platform itself feel *safer and higher quality* than updating an application in Coolify/Dokploy, we win the "I actually trust this in production" argument.

**Must-ship**:
- System Update Coordinator (thin layer on top of the normal deployment engine)
- Tiered execution implemented (agents first/independent, stateless control plane blue-green, stateful Postgres honest about limitations)
- Unified UI surface ("Update Forge") that reuses the same deployment/strategy/rollback components as normal apps
- Pre-flight checks + change plan preview (what versions of agent + api + db will be involved)
- Graceful handover fully exercised and battle-tested
- Automatic + manual rollback paths for the platform itself

**Success criteria**:
- A user can click "Update Forge" in the UI and the entire system (agents + control plane) updates with zero or near-zero downtime for managed applications.
- Failure at any tier produces a clear, actionable explanation + automatic or one-click rollback.
- The experience feels dramatically better than Coolify's auto-update or Dokploy's install script.

**Effort shape**: Medium (most of the hard work is in Phases 1–2 + the existing agent handover code).

---

### Phase 4 — Source-to-Deploy (Git + Builds)
**Why this phase matters**: Once Phases 1–3 exist, developers will demand "just connect my GitHub repo."

**Deliverables**:
- Git source type + webhook support
- Build system (initially simple: `docker build` on the target or dedicated build agents; later Nixpacks/Buildpacks)
- Build logs streaming
- Image promotion + deployment pipeline

**Do not start this phase** until Phase 1 is shipping real value. Many teams will happily deploy from images or their own CI in the early days.

---

### Phase 5 — Breadth, Polish & Ecosystem
Only after the above:
- One-click databases and common services
- Preview / review environments
- Teams + RBAC (beyond the current admin token model)
- Rich templates
- Backup/restore as a first-class concept
- Marketplace or community recipes
- Advanced observability (metrics dashboards, alerting, distributed tracing hooks)

## Quick Wins (High Perception, Relatively Low Effort)

These can run in parallel with Phase 1 and create disproportionate "this feels different" energy:

1. **One-liner agent install** (`curl ... | sh`) that handles enrollment token + binary + systemd service.
2. **Dramatically better security positioning docs** — a single page that clearly explains the trust model difference with diagrams (this alone will get us attention from security-conscious teams).
3. **Public demo environment** (or excellent recorded demo) that shows the enrollment + deploy flow end-to-end.
4. **Agent resource usage + performance numbers** published (Coolify control planes are known to be heavy; we should prove the agent is tiny).
5. **"Update Forge" teaser UI** even before the full flow works (shows the vision and builds anticipation).
6. **Excellent error messages and debugging experience** in the agent and control plane from day one.

## Anti-Patterns We Must Avoid

- Building 50% of ten features instead of 100% of the three that matter (deployment, zero-downtime, self-update).
- Chasing Coolify/Dokploy feature parity on easy things (templates, one-click Postgres) while the core execution + orchestration story is incomplete.
- Making the control plane heavy (we chose Rust + Axum for a reason — keep it light).
- Compromising the security model for convenience (e.g. adding "just SSH for a bit" escape hatches).

## Recommended Immediate Next Steps (Next 4–6 Weeks)

1. **Write the spec for Phase 1** (Application + Deployment models, minimal API surface, UI flows). Use the same rigorous process as the original architecture work.
2. **Create the `crates/core` package** with the first versions of `Application`, `Deployment`, and `DeploymentSpec` (designed for reuse by both control plane and agent).
3. **Stand up a minimal control plane API + DB schema** for applications and deployments (sqlx + migrations).
4. **Build the first end-to-end "deploy from image" flow** (control plane → signed job → agent execution → Traefik labels → working service).
5. **Build the first slice of the operator UI** for this flow (even if very raw).

Once we have a working "I deployed a real container and it stayed up" story, we will have something no one else in this category has: the combination of a best-in-class security model *and* a working product.

---

**This roadmap is deliberately narrow and opinionated.** The original vision was correct: the world does not need another Coolify or Dokploy. It needs the one that takes the security, reliability, and operational honesty problems seriously and actually solves them.

We are closer on the hard parts than anyone realizes. Now we need to close the "can I actually use it?" gap without losing the architectural advantages we've built.

Next action: Do you want me to draft the detailed Phase 1 spec (models + API contracts + UI flows) so we can start executing?