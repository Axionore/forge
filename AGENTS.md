# Forge Project Guidelines

This document contains project-specific instructions for working on Forge.

## Architecture Principles

- **Security is non-negotiable**. The Rust agent on target nodes is the primary security boundary. The control plane should never need root access or Docker socket access to managed servers.
- **Maximize quality over simplicity** when it meaningfully improves developer/operator experience (zero-downtime self-updates, excellent observability, honest failure modes).
- Reuse the core deployment engine for both user applications and "Update Forge" operations (see Section 7 of the design).
- Prefer explicit phasing and strong observability over "magic".

## Rust Guidelines

- Use the workspace `Cargo.toml` for dependencies.
- Prefer `sqlx` with compile-time checked queries for Postgres.
- All agent-to-control-plane communication must be authenticated and attested.
- No unsafe code outside of very narrow, reviewed sections (currently none).

## Frontend Guidelines

- Next.js 16 App Router + React 19 + Tailwind v4 (CSS-first with `@theme`).
- Strict TypeScript (`strict`, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`).
- Reuse deployment UI components for the "Update Forge" flow to maintain consistency.

## Development Workflow

1. All non-trivial features go through the design process (brainstorming → approved sections → implementation).
2. Never ship stubs, TODOs, or half-implemented features in production paths.
3. Run full checks before claiming work is done:
   - `cargo clippy -- -D warnings`
   - `cargo test`
   - `pnpm typecheck && pnpm lint`
   - Relevant Playwright tests when UI is involved

## Important Directories

- `crates/agent/` — The secure execution agent that runs on every managed node.
- `crates/core/` — Shared domain logic, job definitions, strategy engine.
- `services/api/` — Axum control plane API.
- `services/worker/` — Background job processing.
- `apps/web/` — Next.js 16 control plane UI.

## Security Notes

- System updates ("Update Forge") use stricter signing and attestation rules than normal application deployments.
- Agent attestation failures are configurable (block vs allow override with audit).
- Public endpoints support real Let's Encrypt certificates via built-in ACME (HTTP-01 + native TLS termination on 3443 using live rustls config). The xDS gRPC port (18000) uses separate internal mTLS (distinct CA). Never expose the xDS port publicly.

## References

See `docs/adr/` for architectural decisions.
See the main README for high-level vision.