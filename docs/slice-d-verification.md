# Slice D: Phase 1 Verification Harness

**Goal**: Provide repeatable, evidence-based proof that the 7 non-negotiable success criteria from `docs/specs/phase-1-deploy-from-image.md` are met with **zero stubs** in production paths.

**Date**: 2026-06 (post Slice C polish + logs/timelines)

**Status**: Executable artifacts + manual checklist. Full Fresh VM run requires one enrolled agent on real infrastructure.

---

## The 7 Non-Negotiable Criteria (verbatim from spec)

1. A fresh Ubuntu VPS can run the agent via a one-liner (or clear documented steps) and enroll using a token issued from the admin UI.
2. An operator can create an **Application** in the UI, choose one or more enrolled agents as targets, provide a container image (public or with registry credentials), environment variables, published ports, and one or more domains.
3. Clicking "Deploy" results in: a signed `Job::Deploy` over WS → agent executes the full rich `DeploymentSpec` → Traefik labels + automatic Let's Encrypt.
4. The UI shows real-time status (pending → pulling → running → healthy) driven by `JobResult` + heartbeats.
5. Live logs from the container(s) are visible in the UI (via `Job::ContainerLogs` with follow/filter/timestamps/download).
6. Updating the image or env vars and re-deploying performs a replacement (using `previous_spec`).
7. All of the above works end-to-end **without the operator ever giving the control plane SSH or Docker socket access** to the node.

If any step requires manual SQL / curl / editing files on the agent, the phase is incomplete.

---

## Harness Components

### 1. Automated (Playwright) – `apps/web/e2e/phase1-deploy.spec.ts`
Covers UI surfaces for criteria 2, 4, 5, 6 (deploy form, Preview Spec, status, timeline from real JobResults, logs dialog with all enhancements, redeploy).

Requires:
- API + web dev servers running
- At least one enrolled agent (or the test is skipped with clear message)
- `FORGE_ADMIN_TOKEN` in env for the test

See the spec file for exact test cases.

Run:
```bash
cd apps/web
pnpm test:e2e --grep "Phase 1 image deploy"
```

### 2. Manual Fresh VM + End-to-End Checklist (this document)
The authoritative proof for criteria 1, 3, 7 and full integration.

### 3. Evidence Collection
For every run, capture:
- `git rev-parse HEAD`
- `cargo clippy -p forge-agent -p forge-core -- -D warnings` (must be clean)
- `cd apps/web && pnpm lint && pnpm build` (or typecheck)
- Playwright report (html + video/screenshots on failure)
- Screenshots of:
  - Deploy form with private registry + env + ports + strategy
  - Preview Spec modal (exact DeploymentSpec JSON)
  - Post-deploy status + Status Timeline (showing deploy + container_logs + health events)
  - Live Logs dialog (timestamps, filter working, follow ON, line numbers, download button)
  - Redeploy action + new version in timeline
- DB evidence (example):
  ```sql
  SELECT id, job_type, success, error, received_at, details 
  FROM job_results 
  WHERE deployment_id = '...' 
  ORDER BY received_at;
  ```
- Agent journal (on the VM): `journalctl -u forge-agent -n 200 --no-pager`
- Proof of no CP root/Docker access: the only thing the CP ever does is sign jobs and receive results over mTLS/WS.

---

## Fresh VM Verification Steps (Criterion 1 + 7)

**Prerequisites on the VM (Ubuntu 24.04 recommended)**:
- Docker installed and running
- A public domain you control (for Let's Encrypt in criterion 3)

**Step 1: Install & run agent (one-liner or documented)**
```bash
# Example (exact one-liner will be in the enrollment UI)
curl -fsSL https://raw.githubusercontent.com/.../install-agent.sh | bash
# Or manual:
# wget .../forge-agent
# sudo ./forge-agent --enroll-url https://your-cp:3443/enroll?token=...
```

**Expected evidence**:
- Agent starts, prints enrollment instructions or auto-enrolls.
- In UI: the agent appears in the connected list with Ed25519 fingerprint.

**Step 2: Issue enrollment token from UI (no manual DB)**
- Admin UI → Enrollment Tokens → Create
- Copy the token + one-liner

**Step 3: Enroll the agent**
- Paste/run the one-liner on the fresh VPS
- Agent appears healthy in UI

**No root/Docker socket given to CP at any point** — the agent binary is the only thing that talks to Docker.

---

## Full Image Deploy + Observability (Criteria 2-6)

1. Create Application (UI only, no curl).
2. Open the detail page.
3. Fill:
   - Image: `nginx:1.25` (public) or a private image + registry server/username/password
   - Env vars (dynamic editor, including one secret-masked)
   - Published ports (e.g. 80→80)
   - At least one domain for Traefik + LE
   - Strategy: rolling (or blue-green/canary for extra points)
   - Target: the freshly enrolled agent
4. Click **Preview Spec** → confirm the JSON contains `registry_auth`, `env`, `ports`, `domains`, full `DeploymentSpec`.
5. Click **Deploy** (button shows loading state "Signing & dispatching…").
6. Observe:
   - Deployment appears with status `pending` → `in_progress` → `healthy`
   - Status Timeline (in both list and detail) shows real rows from `job_results` (deploy success, container_logs jobs, health_check if emitted)
   - Click "Stream Logs (WS)" → logs dialog opens with:
     - Connection badge (green)
     - Follow: ON (toggle works)
     - Timestamps on every line
     - Filter input (live, with highlight if present)
     - Line numbers
     - Download .log and Copy visible work
     - Auto-scroll + manual pause works
   - Service becomes reachable on the declared domain (HTTP 200, LE cert in browser)
7. Redeploy:
   - Change image tag or an env var
   - Use the "Redeploy" button (in list or detail, using `previous_spec`)
   - New deployment row + new events in the timeline for the same app
   - Old containers stopped, new ones running (zero-downtime not required in Phase 1)

**Registry credentials test (private image)**:
- Same flow with a private image + correct server/user/pass in the form.
- `registry_auth` block appears in the Preview Spec JSON.
- Agent pulls successfully (visible in logs dialog).

---

## Re-run Commands for Evidence (always capture these)

```bash
# Rust side (non-negotiable)
cargo clippy -p forge-agent -p forge-core -- -D warnings

# Frontend
cd apps/web
pnpm lint
pnpm build   # or pnpm typecheck if added

# E2E (when agent present)
pnpm test:e2e --grep "Phase 1 image deploy" --reporter=html
```

---

## Sign-off Checklist (copy into your run log)

- [ ] Criterion 1: Fresh VPS one-liner enroll works, agent visible in UI
- [ ] Criterion 2: Full form (image + private registry + env + ports + domains + targets) works
- [ ] Criterion 3: Signed Job::Deploy executed by agent; service reachable with LE
- [ ] Criterion 4: Real-time status + Status Timeline driven by JobResult rows
- [ ] Criterion 5: Live logs dialog fully functional (timestamps, follow/pause, filter, download, copy)
- [ ] Criterion 6: Redeploy via previous_spec produces new deployment + timeline events
- [ ] Criterion 7: Zero SSH/Docker socket ever given to control plane (agent only boundary)

**Raw evidence attached**:
- Git SHA: __________
- Clippy output: (paste or link)
- pnpm build output: (paste or link)
- Playwright report dir / screenshots: __________
- DB job_results sample: __________
- Agent journal excerpt showing only job execution (no CP control): __________
- Browser screenshot of running service on declared domain with valid LE cert: __________

---

**This harness + the code in Slices A–C completes Phase 1.**

If any criterion cannot be checked off with the above artifacts, the implementation is not done.
