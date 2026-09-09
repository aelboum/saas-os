# ADR-0003: Monorepo with enforced module boundaries

Status: Accepted
Date: 2026-09-06
Supersedes / Superseded by: —

## Context

The repository is currently empty. A structure must be chosen for where Core, Infrastructure, AI Control Plane, and Product code physically live, consistent with the dependency rule in ADR-0001.

## Options Considered

### Option A — Polyrepo (separate repository per layer/product)
- Advantages: hard filesystem-level isolation; independent versioning/release cadence per repo
- Disadvantages: heavy coordination overhead (cross-repo PRs for any Core interface change consumed by Product); slower iteration for a single small team; premature per discovery-doc risk #4

### Option B — Monorepo, single deployable, no internal boundary tooling
- Advantages: fastest to start
- Disadvantages: no structural defense against the Core→Product leak risk; relies entirely on convention

### Option C — Monorepo with physically separate top-level directories per layer (`core/`, `infra/`, `control-plane/`, `products/`) and CI-enforced dependency-graph rules
- Advantages: single build/test/deploy pipeline for a small team; low coordination overhead; the physical separation gives the CI lint rule (ADR-0001) a clear graph to check; does not preclude splitting a module into its own deployable or repo later, since the internal boundary already exists in the import graph
- Disadvantages: requires the lint tooling to actually be wired up (Phase 1) for the boundary to be real, not just organizational

## Recommendation

Option C.

## Decision

Accepted. Repository structure follows `docs/ARCHITECTURE.md` §3. Boundary enforcement (dependency-cruiser or equivalent, per `docs/ARCHITECTURE.md` §8) is scheduled in Phase 1.

## What Would Be Difficult to Change Later

Migrating from monorepo to polyrepo later is a mechanical (if tedious) split, not a redesign, *provided* module boundaries were real from the start. If they were not, the split additionally requires untangling accidental coupling first.

## Related

ADR-0001; `docs/ARCHITECTURE.md` §3, §8.
