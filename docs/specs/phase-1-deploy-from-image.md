# Phase 1 Spec: Deploy from Container Image

**Status**: Draft for review  
**Date**: 2026-06  
**Goal**: Make Forge usable for the first time. A developer can enroll nodes and deploy a real container image (public or private) to get a working, routable service with visible logs and status.  
**Primary Success Metric**: End-to-end demo works reliably on fresh infrastructure without manual agent hacking.

This phase deliberately **does not** include Git sources, builds, one-click databases, or advanced strategies. Those come later. The focus is "the engine is real and I can use it."

---

## 1. Success Criteria (Non-Negotiable)

By the end of this phase, the following must be true with **no stubs**:

1. A fresh Ubuntu VPS can run the agent via a one-liner (or clear documented steps) and enroll using a token issued from the admin UI.
2. An operator can create an **Application** in the UI, choose one or more enrolled agents as targets, provide a container image (public or with registry credentials), environment variables, published ports, and one or more domains.
3. Clicking "Deploy" results in:
   - A signed `Job::Deploy` being sent to the relevant agent(s) over the existing WebSocket.
   - The agent executing the rich `DeploymentSpec` (reusing the already-maximized Docker surface).
   - Traefik labels automatically applied so the service is reachable on the specified domain(s) with automatic Let's Encrypt.
4. The UI shows real-time status (pending → pulling → running → healthy) driven by `JobResult` + heartbeats from the agent.
5. Live logs from the container(s) are visible in the UI (via `Job::ContainerLogs`).
6. Updating the image or env vars and re-deploying performs a replacement (initially simple stop/start of old containers; zero-downtime comes in Phase 2).
7. All of the above works end-to-end without the operator ever giving the control plane SSH or Docker socket access to the node.

If any of the above requires manual SQL, curl, or editing files on the agent, the phase is not complete.

---

## 2. Core Domain Model

### 2.1 Key Concepts

- **Application**: Logical workload owned by the user (e.g. "api", "web-frontend", "worker"). Has a name, description, and desired state.
- **Deployment**: A concrete desired state for an Application at a point in time. Contains the `DeploymentSpec` (or a superset that compiles down to it).
- **Target**: Where the deployment should run. In Phase 1 this is explicitly one or more enrolled `Agent`s. (Later this can become labels, regions, etc.)
- **Source** (future-proofing): For Phase 1 only `ContainerImage` variant is implemented.

### 2.2 Rust Types (proposed location: `crates/core/src/deploy.rs` or `crates/types`)

```rust
// crates/core/src/models.rs (or similar)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    // later: owner, team, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub id: Uuid,
    pub application_id: Uuid,
    pub version: i32,                    // monotonic per application
    pub spec: DeploymentSpec,            // reuse the rich type from the agent
    pub status: DeploymentStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeploymentStatus {
    Pending,
    InProgress,
    Healthy,
    Unhealthy,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerImageSource {
    pub image: String,                   // "ghcr.io/org/app:v1.2.3" or "nginx:1.25"
    pub registry_credentials_id: Option<Uuid>, // reference to stored auth (Phase 1: simple)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentTarget {
    pub agent_id: Uuid,
    pub replicas: u32,                   // Phase 1: usually 1; Swarm later
}
```

**Important design decision**: `DeploymentSpec` from `crates/agent` is **the source of truth** for what the agent executes. The control plane stores a higher-level view but must be able to produce a valid `DeploymentSpec` for signing.

We should move `DeploymentSpec`, `ContainerSpec`, etc. into `crates/core` (or `crates/types`) in this phase so both agent and control plane depend on the same definitions. This is a small refactor with high long-term value.

---

## 3. Database Schema Additions

New migration `0003_phase1_deployments.up.sql`:

```sql
CREATE TABLE applications (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE deployments (
    id UUID PRIMARY KEY,
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    spec JSONB NOT NULL,                    -- serialized DeploymentSpec (rich)
    status TEXT NOT NULL,                   -- 'pending', 'in_progress', etc.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (application_id, version)
);

CREATE TABLE deployment_targets (
    deployment_id UUID REFERENCES deployments(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    replicas INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (deployment_id, agent_id)
);

CREATE TABLE registry_credentials (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    registry_host TEXT NOT NULL,
    username TEXT,
    password_encrypted BYTEA,               -- KMS-wrapped in future; for now simple
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Helpful indexes
CREATE INDEX idx_deployments_app ON deployments(application_id, version DESC);
CREATE INDEX idx_deployment_targets_agent ON deployment_targets(agent_id);
```

For Phase 1 we accept storing the full `DeploymentSpec` as JSONB (the agent already deserializes it). This is pragmatic. Later we can normalize further if needed.

Add `last_heartbeat_at` and basic capacity fields to `agents` table in the same migration for future scheduling.

---

## 4. Control Plane API Surface (Axum)

All admin routes continue to require `X-Admin-Token`.

### Core Endpoints (MVP)

**Applications**
- `GET    /admin/applications`
- `POST   /admin/applications` → `{ name, description? }`
- `GET    /admin/applications/{id}`
- `PATCH  /admin/applications/{id}` (name/desc only in Phase 1)

**Deployments**
- `POST   /admin/applications/{app_id}/deployments` 
  - Body: `{ spec: DeploymentSpec, targets: [{agent_id, replicas}], registry_credentials? }`
  - Creates a new versioned Deployment, persists it, then triggers dispatch.
  - Returns 201 with the new deployment.

- `GET    /admin/applications/{app_id}/deployments/{deployment_id}`
- `GET    /admin/applications/{app_id}/deployments` (list, latest first)

**Dispatch & Control**
- `POST   /admin/deployments/{id}/deploy` — idempotent trigger to send jobs to targets.
- `POST   /admin/deployments/{id}/stop` — sends `Job::Stop` to targets.

**Agent-facing (WebSocket + callbacks)**
- `GET    /agent/ws` (upgrades to WebSocket)
  - Auth: The agent sends its `agent_token` (issued at enrollment) in the first message or as subprotocol / header.
  - Once authenticated, the connection is used for:
    - Outbound: `Job` messages (signed)
    - Inbound: `AgentMessage::Heartbeat` and `AgentMessage::JobResult`

**Logs & Debugging (Phase 1)**
- `POST   /admin/deployments/{id}/containers/{container}/logs` — proxies to agent `Job::ContainerLogs` and streams result.

### Error Handling
Continue using the `ProblemDetail` style already implemented. All state-changing operations on deployments must be idempotent where possible.

---

## 5. Job Dispatch & WebSocket Integration

This is the most important new plumbing.

### 5.1 Control Plane WS Handler (new code in `services/api`)

We currently only have outbound WS from agent. We need the server side:

- Accept WebSocket at `/agent/ws`
- First message from agent must authenticate using its `agent_token` (compare hash against `agents.agent_token_hash`)
- Maintain a map of `agent_id -> WebSocket sender` (protected by RwLock or channel-based actor)
- When we want to deploy, look up the agent's connection and send a `SignedJob`
- Receive `AgentMessage` (Heartbeat + JobResult) and:
  - Update `agents.last_seen_at`
  - Persist `JobResult` (new table `job_results` recommended)
  - Update deployment status based on results

### 5.2 Signing
The control plane already generates an ephemeral Ed25519 key in `EnrollmentService`. We need a proper long-lived signing key (loaded from env or file/KMS in production) and expose `sign_job(job: &Job) -> SignedJob`.

For Phase 1 we can keep the key in memory (same as enrollment) but document that it must be persisted + backed up for real use.

### 5.3 Reconciliation
On every heartbeat or JobResult, the control plane should compare desired state (latest Deployment for each Application on that agent) vs. reported reality and surface drift in the UI.

---

## 6. UI Flows (Next.js 16 + Tailwind 4)

Location: `apps/web/app/admin/applications/...` and `apps/web/app/admin/deployments/...`

### Minimum Screens (high polish required)

1. **Applications List** (`/admin/applications`)
   - Table: Name | Latest Version | Status (aggregated) | Targets (agent hostnames) | Last Deployed | Actions (View, Deploy New)

2. **Application Detail + New Deployment Form**
   - Left: current desired state summary
   - Big "New Deployment" card:
     - Image input (text)
     - Registry credentials selector (or inline simple auth for Phase 1)
     - Environment variables (nice key/value editor, add/remove)
     - Ports (published + expose)
     - Domains (multi input, Traefik will get `Host(...)` rules)
     - Target agents: multi-select from enrolled agents + replicas per target
   - "Preview Spec" button that shows the generated `DeploymentSpec` JSON (educational + debug)
   - Deploy button (disabled until valid)

3. **Deployment Detail**
   - Status timeline (based on JobResults)
   - Live logs panel (tabs per container, follow toggle)
   - Current containers running on each target (from heartbeats or explicit `ContainerTop`)
   - "Redeploy" and "Rollback to previous version" actions

4. **Global Logs / Activity** (stretch for Phase 1)

**Design principles for UI in this phase**:
- Every action must have clear loading + error states.
- Status must always reflect reality from the agent, not just what we last sent.
- The one-time secret pattern we used for enrollment tokens should be reused for any sensitive values shown once (e.g. temporary debug tokens).

---

## 7. Security & Hardening Notes (Phase 1)

- All deployment operations require admin token (same as enrollment today).
- Agent authentication on `/agent/ws` must be constant-time and rate-limited.
- Registry credentials stored in DB must be encrypted at rest before Phase 1 ships to real users (even a simple envelope with a key from env is acceptable for now).
- Never log image pull credentials or full environment variable values.
- The rich `DeploymentSpec` already supports many security options (`cap_drop`, `read_only`, `security_opt`, etc.). The UI should expose the important ones early.

---

## 8. Incremental Delivery Plan (Inside Phase 1)

Do **not** attempt to ship everything at once. Recommended slices:

**Slice 1 (Foundation)**
- Move `DeploymentSpec` family into `crates/core`
- New DB tables + basic CRUD for Application + Deployment (admin only)
- One working `POST /admin/.../deployments` that just stores state

**Slice 2 (Dispatch)**
- Implement WS server handler + agent auth
- Wire job signing + sending `Job::Deploy`
- Agent already knows how to execute it — verify end-to-end with curl + manual UI

**Slice 3 (Basic UI + Traefik)**
- Applications list + create deployment form
- Generate proper Traefik labels in the spec
- Status polling + simple logs

**Slice 4 (Polish & Hardening)**
- Live log streaming
- Registry auth
- Reconciliation on heartbeat
- Error states and recovery paths

Only declare Phase 1 complete when Slice 4 is done and the success criteria above are met with real users.

---

## 9. Open Questions / Decisions Needed

1. Should `DeploymentSpec` live in `crates/core` or a new `crates/types` crate that both agent and api depend on? (Recommendation: `crates/core`)
2. How do we handle private registry auth in Phase 1? (Simple username/password stored encrypted vs. pulling from agent-side docker config.)
3. Do we require at least one healthcheck definition in the first version of the form, or make it optional?
4. Naming: Are we calling the top-level concept "Application" or "Service" or "Workload"?

---

## 10. Verification Plan

Before merging anything that claims "Phase 1 complete":

- Fresh VM test: one command to start api + web, issue token, enroll agent, deploy `nginx` or a test image, reach it on a domain.
- All critical paths have automated tests where feasible (sqlx tests for schema, integration test for job roundtrip using Mock + real WS handler).
- `cargo clippy -D warnings` clean on new code.
- `pnpm lint && pnpm typecheck` clean.
- Manual security pass: no secret leakage, proper authz on every new endpoint.

---

**This spec is intentionally ambitious but scoped.** It reuses almost everything already built in the agent. The majority of new work is orchestration, state management, and the first real pieces of the control plane product surface.

Once this document is reviewed and approved, the next step is to begin Slice 1 implementation.

---

*End of Phase 1 Spec*