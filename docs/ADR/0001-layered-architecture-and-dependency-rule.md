# ADR-0001: Layered architecture and the core dependency rule

Status: Accepted
Date: 2026-09-06
Supersedes / Superseded by: —

## Context

`saas-os` must serve as a reusable foundation for multiple future SaaS products, starting with Dograh, without becoming permanently coupled to any one product's domain. The single greatest risk identified in `docs/ARCHITECTURE-DISCOVERY.md` (§23) is Core absorbing product-specific logic by convenience. A structural rule is needed that survives deadline pressure, not just a stated intention.

## Options Considered

### Option A — No enforced boundary; discipline by convention only
- Advantages: fastest to start, no tooling investment
- Disadvantages: convention erodes under deadline pressure (discovery doc risk #6); the exact failure mode this platform exists to avoid

### Option B — Four-layer model (Core / Infrastructure / AI Control Plane / Product) with a directional dependency rule, enforced by physical directory separation + CI dependency-graph lint
- Advantages: makes "core depends on product" a build failure, not a code-review judgment call; gives a clear mental model for where any new code belongs; supports splitting into separate deployables later without a rewrite
- Disadvantages: upfront tooling cost (lint rule, CI check); requires discipline to classify new code correctly at write-time

### Option C — Full separate repositories per layer from day one
- Advantages: strongest possible enforcement (no shared build graph to leak across)
- Disadvantages: heavy coordination overhead for a pre-scale platform with one team and one real product; premature per `docs/ARCHITECTURE-DISCOVERY.md` §23 risk #4

## Recommendation

Option B.

## Decision

Accepted. The platform is structured as four layers (Core, Infrastructure, AI Control Plane, Product) with the dependency rule defined in `docs/ARCHITECTURE.md` §2: Product depends on Core and Infra; Core never depends on Product; AI Control Plane interacts with Core and Product only through explicitly declared tools/interfaces. Enforcement (dependency-graph lint in CI) is scheduled for Phase 1 of `docs/IMPLEMENTATION-ROADMAP.md`.

## What Would Be Difficult to Change Later

If Product code is written against Core internals (rather than published abstractions) before enforcement tooling exists, every such call site becomes a manual audit-and-refactor task under pressure, and the boundary stops being trustworthy. Enforcement must exist before the first Product module is written.

## Related

`docs/ARCHITECTURE.md` §1–§2, §8; ADR-0003; ADR-0004.
