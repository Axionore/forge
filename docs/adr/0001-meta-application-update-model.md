# ADR 0001: Meta-Application Model for Platform Self-Updates

## Status
Accepted

## Context
We need a way to deliver zero-downtime, high-availability updates to Forge itself (the control plane + agents) while maintaining a consistent, high-quality user experience.

Coolify and Dokploy both suffer from painful, risky, and sometimes breaking updates to the platform. Users frequently express fear around upgrading the control plane.

## Decision
We will model updates to Forge itself ("Update Forge") as a special case of the normal deployment system using a **Meta-Application** pattern:

- The same deployment engine, strategy engine (rolling/blue-green/canary), health checking, and rollback mechanisms are reused.
- A thin "System Update Coordinator" layer decides the execution strategy per tier (agents vs stateless control plane vs stateful control plane).
- The user experiences a single unified "Update Forge" flow that feels identical to deploying their own applications.

## Consequences
- Strong reuse reduces duplication and improves long-term quality.
- We must maintain very clean boundaries between normal deployment logic and system update concerns.
- Tiered execution (especially for Postgres) requires honest communication with the user.
- This design directly supports our goal of being superior in operational safety and developer experience.

## Date
2026-05-27