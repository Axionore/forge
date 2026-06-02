# Spec: Source-to-Deploy + Multi-Cloud Provider + Supply-Chain Security

Status: DRAFT (parity matrix to be finalized from in-flight Coolify/Dokploy/Hetzner research)
Owner: Charles
Branch: `feat/source-to-deploy` (off `feat/phase2-rollback-and-0016-foundation` → `main`)

## Context

Forge already has the hard parts: a signed-job control plane (no standing SSH), zero-downtime
strategies (rolling/blue-green/canary with statistical promotion + Envoy xDS), age-encrypted
secrets, agent enrollment with attestation hooks, RBAC, a basic Hetzner provisioner, and scaffolds
for catalog/git-sources/webhooks/backups/notifications. What it lacks — and what Coolify and
Dokploy are built around — is the **source-to-deploy loop**: connect a Git repo, build an image
(Nixpacks / Dockerfile / Compose), and ship it on push. This spec closes that gap, makes
"deploy to any cloud" real via a `CloudProvider` trait (full Hetzner lifecycle now, other clouds
stubbed), and turns Forge's existing zero-SSH posture into a **provable supply-chain-security**
differentiator no incumbent matches.

## Competitor baseline — parity matrix (PRELIMINARY; finalize from research)

Legend: ✅ have · �ðŸ"¶ partial/scaffold · ❌ gap · ⏭ deliberately deferred

| Capability                                   | Coolify       | Dokploy        | Forge today                     | This spec                   |
| -------------------------------------------- | ------------- | -------------- | ------------------------------- | --------------------------- |
| Git connect (GitHub/GitLab/Bitbucket/Gitea)  | ✅            | ✅             | ◐ git_sources + webhook handler | **build the full flow**     |
| Deploy on push (webhook)                     | ✅            | ✅             | ◐ webhook verify (now HMAC)     | ✅ wire to build            |
| Build: Nixpacks                              | ✅            | ✅             | ❌                              | ✅                          |
| Build: Dockerfile                            | ✅            | ✅             | ◐ BuildSpec type                | ✅                          |
| Build: Docker Compose (native)               | ✅            | ✅             | ❌                              | ✅                          |
| Build: Buildpacks (Paketo)                   | ❌            | ✅             | ❌                              | ⏭ scaffold                 |
| Build log streaming                          | ✅            | ✅             | ◐ log WS infra exists           | ✅                          |
| Preview / PR environments                    | ✅            | ◐              | ◐ preview deploy path           | ✅ finish                   |
| One-click service catalog                    | ✅ (280+)     | ✅ (templates) | ◐ (pg/redis/minio + buildpacks) | ⏭ expand later             |
| Databases + scheduled backups (S3)           | ✅            | ✅             | ◐ schema + Job::Backup          | ⏭ later phase              |
| Auto SSL / Let's Encrypt + custom domains    | ✅            | ✅             | ◐ ACME in api + Traefik labels  | ✅ via DNS+ingress          |
| Multi-server                                 | ✅            | ✅             | ✅ (multi-agent)                | ✅                          |
| Teams / RBAC                                 | ✅            | ✅             | ◐ RBAC scaffold                 | ⏭ later phase              |
| Monitoring + alerts                          | ✅ (sentinel) | ✅             | ◐ metrics + heartbeat           | ⏭ later phase              |
| Notifications (Discord/Slack/Telegram/email) | ✅            | ✅             | ◐ audit-only                    | ⏭ later phase              |
| API + CLI                                    | ✅            | ✅             | ◐ API; ❌ CLI                   | ⏭ CLI later                |
| Browser terminal + live logs                 | ✅            | ✅             | ✅                              | ✅                          |
| Cloud provisioning                           | ❌ (SSH only) | ❌ (SSH only)  | ◐ Hetzner basic                 | **✅ full Hetzner + trait** |
| Zero-downtime canary + auto-rollback         | ◐ fragile     | ◐ basic        | ✅ statistical + xDS            | ✅                          |
| No standing SSH / signed jobs                | ❌            | ❌             | ✅                              | ✅                          |

Neither incumbent can provision cloud infrastructure (both require a pre-existing server + SSH).
Forge's `CloudProvider` + zero-SSH model is already beyond parity there.

## Our differentiator — provable supply-chain security (SLSA-aligned)

Built on the existing Ed25519 signed-job root of trust. No incumbent offers this:

1. **Signed, attested build artifacts.** Every image the build pipeline produces is signed with
   `cosign` (keyless or KMS); a **SLSA provenance** attestation records the source commit, builder
   identity, and build parameters. Agents **verify the signature + provenance before run** — an
   unsigned/altered image is refused (fail-closed), extending the signed-job guarantee to images.
2. **Zero standing SSH, attested nodes.** Enrollment already takes cloud/TPM attestation; make it
   enforce a policy (e.g. require Hetzner/AWS attestation for a node to receive prod jobs).
3. **Hermetic-ish builds.** Builds run in the agent's isolated Docker context, secrets injected via
   age to tmpfs (never baked into layers), build inputs pinned by commit SHA + digest.
4. **Auditable chain.** `audit_logs` (0016) records who triggered which build of which commit to
   which image digest deployed where — a verifiable chain from commit → image → running container.

This is the headline: "Coolify/Dokploy give you Heroku on your servers; Forge gives you a
cryptographically verifiable supply chain from git push to running container, on infra it can
provision for you — with no standing SSH."

## Security requirements (ASVS L2; builds touch RCE + external integration → STRIDE required)

- **A05/A08 (build = arbitrary code execution):** builds run only inside the agent's Docker sandbox,
  resource-limited (CPU/mem/time/disk), network-egress considered, never on the control plane.
  Build inputs pinned by commit SHA. No `eval` of repo content on the CP.
- **A01/A07:** every build/deploy/provision endpoint behind admin auth + per-action RBAC
  (`builds:create`, `cloud:provision`, default-deny). Git tokens + cloud API tokens are age-encrypted
  at rest (reuse the secret store), never logged.
- **A08 (integrity):** webhook HMAC already fixed; build artifacts cosign-signed + provenance-attested;
  agents verify before run.
- **A10 (fail-closed):** failed build → no deploy; failed signature/provenance verify → refuse run;
  partial provisioning → rollback/cleanup of created cloud resources.
- **A09:** structured audit of build + provision events; never log secrets, git tokens, or cloud
  API tokens.
- STRIDE threat model: `specs/threat-model-source-to-deploy.md` (write before coding builds).

## CloudProvider trait (Hetzner full lifecycle now; AWS/GCP/Azure/DO stubbed)

`crates/providers` defines a `CloudProvider` async trait; `crates/providers/hetzner` implements it
fully; other clouds get a `crates/providers/<name>` returning `ProviderError::NotImplemented` from
each method (compiles, listed in UI as "coming soon"). Final method set finalized from the Hetzner
API research; provisional surface:

```
provision_server, get_server, list_servers, delete_server, rescale_server
create_ssh_key / ensure_ssh_key
create_firewall, apply_firewall, delete_firewall
create_network, attach_server_to_network, delete_network
create_volume, attach_volume, detach_volume, delete_volume
create_load_balancer, add_lb_target, lb_health, delete_load_balancer
create_floating_ip / primary_ip, assign_ip
dns_list_zones, dns_upsert_record, dns_delete_record   (Hetzner DNS = separate API/token)
capabilities() -> set   // so the UI greys out what a provider can't do
```

Partial-failure cleanup is mandatory (track created resource IDs; on error, best-effort teardown).
Cloud API tokens stored via the age secret store (0017 hetzner_credentials already exists).

## Delivery plan (phased; verify + commit each)

- **Phase A — Provider abstraction + full Hetzner lifecycle.** `CloudProvider` trait, Hetzner impl
  (servers/firewalls/networks/volumes/LBs/floating-IPs/DNS), stub crates for AWS/GCP/Azure/DO,
  API endpoints + UI surface, partial-failure cleanup. Agent: rust-engineer. Tests: provider unit +
  `#[sqlx::test]` for credential storage; Hetzner calls behind a mockable HTTP client.
- **Phase B — Source-to-deploy.** `BuildSpec` (nixpacks|dockerfile|compose|buildpack-stub); agent
  build executor (run nixpacks/`docker build`/compose in sandbox, stream logs over existing WS);
  Git fetch by commit; deploy-on-push wired to webhook; build records + status; UI build view.
  Agents: rust-engineer (agent/build), security-engineer (sandboxing + secret injection).
- **Phase C — Supply-chain differentiator.** cosign sign + SLSA provenance on build output;
  agent verifies signature/provenance before run (fail-closed); attestation-policy on enroll;
  audit chain commit→digest→deploy. Agent: security-engineer.

## Verification

Each phase: `cargo clippy --all-targets --workspace -- -D warnings` clean; `cargo test --workspace`
green; `pnpm build` green; affected pages render 0 console errors (Playwright); for Hetzner, an
opt-in integration test gated on `FORGE_HETZNER_TEST_TOKEN` (skips in CI without it). End-to-end
demo: connect a public Git repo → Nixpacks build → signed image → deploy → visit URL, on a
Hetzner-provisioned server, with the control plane never holding SSH.
