# End-to-End Manual Testing: Git Sources + Preview Deployments (Tier 1)

This guide allows real testing with actual GitHub or GitLab repositories (push + PRs). It exercises the full flow: connect form → webhook → preview deployment creation + auto-deploy → preview cards in UI → Promote/Destroy actions.

**Prerequisites (one-time)**
- Running Forge control plane (API on :3000, at least one connected agent with Docker feature).
- At least one Application created in the UI (the webhook uses the first app as fallback for previews).
- A real GitHub or GitLab account + repo you control (can be private; use a throwaway repo for safety).
- Admin token for UI.

**Step 1: Connect a Git Source via the nice connect form**
1. Open Admin → Deployments.
2. Click "Git Sources" button (opens the polished dialog).
3. In "Connect New Source":
   - Name: e.g. "my-test-repo"
   - Provider: GitHub or GitLab
   - Webhook Secret: generate a strong random string (e.g. `openssl rand -hex 32`). Copy it.
   - (Optional) Access Token: your PAT if you want future richer picker/repo listing.
4. Submit. Note the returned Source ID (short prefix shown in list).

**Step 2: Configure the real webhook on GitHub/GitLab**
- Go to your repo → Settings → Webhooks (GitHub) or Settings → Webhooks (GitLab).
- Add webhook:
  - Payload URL: `http://YOUR_FORGE_HOST:3000/webhooks/git/<SOURCE_ID>` (use ngrok / local tunnel / public IP if testing from internet; for local GitHub webhooks use https://smee.io or similar relay if behind NAT).
  - Content type: application/json
  - Secret: paste the exact webhook_secret from Step 1.
  - Events: Just the push event (and Pull requests for PR previews).
  - Active: yes.
- Save. GitHub/GitLab will send a ping (you can ignore or check logs).

**Step 3: Trigger a real event and observe preview creation + deployment**
- Make a commit + push to the repo (or open a PR).
- Watch API logs (should show "git_webhook_handler", signature handling, preview deployment created, and "Dispatched preview Deploy job..." thanks to the e2e quick fix).
- In the UI:
  - Refresh Deployments list.
  - A new deployment appears (name like "repo-pr-123" or "repo-push-sha").
  - It has `git_source_id`, so in the detail view you see the "This is a Git Preview" section with **Promote to Production** and **Destroy Preview** buttons (real wired actions).
  - Because of the auto-dispatch fix in the webhook handler, the preview containers should appear as running on any connected agents (check `docker ps` on the agent host for the "preview" container).

**Step 4: Test the preview cards + Promote/Destroy (real job dispatch)**
- Open the preview deployment detail.
- Click "Promote to Production":
  - It finds/updates a stable deployment for the app (or falls back), updates spec with the preview image/commit, dispatches real `Job::Deploy` to agents (cutover simulation), marks the preview "promoted".
  - UI refreshes; status changes.
- Click "Destroy Preview" (with confirm):
  - Dispatches real `Job::Stop` for the preview containers to connected agents.
  - Marks deployment "destroyed".
  - Containers stop on the agent(s). UI refreshes, deployment gone or marked destroyed.

**Step 5: Test PR vs Push, multiple sources, error cases**
- Open a PR on the repo → new preview appears (is_pr=true in payload).
- Push directly → another preview.
- Add a second Git Source in the UI and repeat with a different repo.
- Bad signature: temporarily change secret in Git provider → webhook still accepted in v1 (with warning log) but you see the behavior.
- No applications yet: webhook returns helpful note.

**Troubleshooting / Quick Fixes Applied in This Slice**
- Signature validation relaxed (strips "sha256=" prefix, non-fatal for testing; production should use proper constant-time HMAC with ring).
- Auto-dispatch of the preview `Deploy` job on successful webhook (so you actually see containers without manual intervention or waiting for agent heartbeat reconciliation).
- UI buttons now call the real /promote and /destroy endpoints (with loading via refresh).
- Preview deployments get proper git metadata (git_source_id, commit_sha, ref) so the "Git Preview" section and promote/destroy cards appear automatically.

**Expected Production Polish Notes (post Tier 1)**
- Proper constant-time HMAC validation + better provider-specific parsing.
- Real repo/PR picker in the connect dialog (using the access_token).
- Stable "main" deployment association per git source (instead of dummy first-app fallback).
- Targets resolved at webhook time or via label matching on agents.

This flow is now fully testable end-to-end with real external Git providers. Run the steps above, observe logs, UI updates, and agent `docker ps` / container behavior.

If anything fails, share the exact error + logs for a targeted quick fix.