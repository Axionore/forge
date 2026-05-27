# Forge

**The most secure, cloud-agnostic, and operationally excellent open-source self-hosted deployment platform.**

Forge combines the best ideas from Coolify and Dokploy, fixes their critical shortcomings (especially the dangerous SSH + Docker socket trust model), and adds production-grade capabilities that neither platform has delivered well — starting with first-class zero-downtime deployments and high-availability updates, even for the platform itself.

## Core Philosophy

- **Security by default**: Every target node runs a lightweight, capability-based Rust agent. The control plane never holds root SSH access or Docker socket privileges.
- **Free public TLS out of the box**: The control plane includes first-class Let's Encrypt (ACME) support. When you configure `ACME_DOMAINS`, it automatically obtains and renews real certificates, runs the required HTTP-01 challenge responder on port 80, **and natively terminates TLS** for the main API on port 3443 using the live certificates. Static certs are also supported via `TLS_CERT_PATH` / `TLS_KEY_PATH`.
- **Unified experience**: Updating Forge itself uses the same high-quality deployment strategies, UI, rollback, and observability as your own applications.
- **Maximized features**: We deliberately choose the ambitious path when it delivers meaningfully better developer and operator experience.
- **Cloud & VPS agnostic**: Excellent first-class support for Hetzner, DigitalOcean, bare metal via SSH, with a clean provider abstraction for more.

## Technology

- **Control Plane**: Next.js 16 + TypeScript (strict) + Tailwind v4
- **Core & Agent**: Rust 1.95+ (Axum, Tokio, sqlx, bollard)
- **Database**: PostgreSQL 18
- **Agent Model**: Signed jobs, attestation, graceful handover, WireGuard mesh support

## Current Status

This project is in early active development. The foundational architecture for zero-downtime updates (including self-updates of Forge) has been designed with maximum ambition.

**Roadmap & Competitive Positioning**: See [docs/roadmap-competitive-advantage.md](./docs/roadmap-competitive-advantage.md) for the honest gap analysis against Coolify/Dokploy and the prioritized path to becoming a real threat on the dimensions that matter (security model, execution quality, zero-downtime, and platform self-update safety).

## Getting Started (Development)

```bash
# Rust side
cargo build

# Frontend
cd apps/web
pnpm install
pnpm dev
```

## License

Apache-2.0 (with MIT option for maximum compatibility).# forge
