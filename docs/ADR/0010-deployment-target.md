# ADR-0010: Deployment target platform

Status: Accepted
Date: 2026-09-06
Supersedes / Superseded by: —

## Context

The platform needs a deployment target for its containerized deployable unit(s) (`docs/DEPLOYMENT-ARCHITECTURE.md` §1).

## Options Considered

### Option A — Docker + Docker Compose + a single VPS
- Advantages: minimal operational surface and cost for the current stage (small team, one real product not yet integrated); full control over the host; no managed-platform lock-in; straightforward mental model (one or a few Compose files describe the whole running system)
- Disadvantages: no built-in horizontal scaling, rolling deploys, or multi-region story; a single VPS is a single point of failure unless deliberately mitigated; scaling beyond one host requires either manual orchestration or a later migration

### Option B — Managed container platform (Fly.io, Render, Cloud Run, ECS)
- Advantages: some managed scaling/rolling-deploy features without full Kubernetes complexity
- Disadvantages: recurring platform cost and a degree of platform-specific coupling not justified before the platform has real production load

### Option C — Self-managed Kubernetes
- Advantages: maximum control and portability; industry-standard for large-scale multi-service platforms
- Disadvantages: significant operational overhead for a small team at this stage; explicitly premature per `docs/ARCHITECTURE-DISCOVERY.md` §4 non-goals

## Recommendation

Option A, with deployment interfaces designed so Option B/C become addable later without redesigning the deployment-facing parts of the platform.

## Decision

**Accepted.** Initial deployment target is **Docker containers, orchestrated with Docker Compose, running on a single VPS.** Kubernetes is explicitly **not** implemented at this stage.

To keep this reversible, `infra/deploy` defines a **deployment-target interface** — build image, push/publish, deploy, run health check (`docs/DEPLOYMENT-ARCHITECTURE.md` §7), and roll back (`docs/DEPLOYMENT-ARCHITECTURE.md` §6) — implemented first for Docker Compose + VPS. Every other part of the CI/CD pipeline (`docs/DEPLOYMENT-ARCHITECTURE.md` §5, stages 1–4: lint/boundary check, test, security scan, build) is deployment-target-agnostic and must not encode Compose- or VPS-specific assumptions, so that a later target implementation (Kubernetes, or a managed platform) plugs into the same upstream pipeline without those stages changing.

## Rejected Alternatives

- **Managed container platform (Option B)**: not rejected outright — it remains a plausible *next* step (see Future Migration path) — but not adopted as the initial target, since it adds recurring cost and platform coupling ahead of demonstrated need.
- **Kubernetes (Option C)**: rejected for now — explicitly premature at this stage per the platform's stated non-goals; the operational overhead is not justified without a scale or multi-service deployment need that does not yet exist.

## Future Migration / Extension Path

When scale, reliability, or multi-region requirements demand it, a new implementation of the `infra/deploy` deployment-target interface can be built for a managed container platform or Kubernetes, without rewriting CI stages 1–4 or any application code — provided the interface boundary described in the Decision above is respected from the first implementation, not treated as an afterthought once Compose-specific assumptions have already leaked upstream.

## What Would Be Difficult to Change Later

Nothing here is a one-way door provided the modular-monolith-with-real-boundaries approach (ADR-0001, ADR-0003) and the deployment-target interface boundary above both hold — moving from Docker Compose + VPS to Kubernetes later is an infrastructure migration behind an existing interface, not an architecture rewrite. The risk is if Compose- or VPS-specific assumptions (e.g., a hardcoded single-host filesystem path, a hardcoded `docker-compose` CLI call from application code) leak into Core, Product, or CI stages that should be deployment-target-agnostic — that is the actual thing to guard against, not the target choice itself.

## Related

`docs/DEPLOYMENT-ARCHITECTURE.md`; `docs/ARCHITECTURE-DISCOVERY.md` §16; ADR-0007 (Redis avoids adding cloud-managed-queue coupling that would sit oddly with this target).
