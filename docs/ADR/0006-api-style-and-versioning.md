# ADR-0006: API style and versioning

Status: Accepted
Date: 2026-09-06
Supersedes / Superseded by: —

## Context

The platform's external API is what tenants, their end users, and third-party integrations (including Dograh once integrated) depend on. It must be settled before the first external route ships (`docs/API-ARCHITECTURE.md` §8).

## Options Considered

### Option A — REST, documented with OpenAPI, versioned via URL path segment (e.g., `/v1/...`) from the first release
- Advantages: broadest tooling/client compatibility; simplest external auth story; explicit and visible versioning; OpenAPI gives a machine-readable, generatable source of truth (docs, client SDKs, contract tests)
- Disadvantages: over-fetching/under-fetching for complex client needs; multiple versions to maintain in parallel during transitions

### Option B — GraphQL
- Advantages: flexible client-driven queries; single endpoint
- Disadvantages: bigger upfront investment; schema federation across the Core/Product boundary is itself a hard sub-problem; less familiar external-integrator tooling than REST; versioning conventions are less standardized

### Option C — RPC-style (tRPC, gRPC)
- Advantages: strong end-to-end typing if the whole stack shares a language (tRPC); efficient for internal service-to-service calls (gRPC)
- Disadvantages: couples client/server more tightly (tRPC); less suited to an external, third-party-consumed API; weaker fit for the "many future unknown consumers" goal

## Recommendation

Option A.

## Decision

**Accepted.** The external API surface is REST, specified with OpenAPI as the source of truth (`docs/API-ARCHITECTURE.md` §5), and versioned from the first released route using a URL path segment (`/v1/...`). No external route is ever released unversioned. Internal (Core ↔ Product ↔ AI Control Plane) calls may use REST as well for consistency, unless a later ADR justifies a different internal-only mechanism — that choice does not affect the external contract, since the two surfaces are already architecturally distinct (`docs/API-ARCHITECTURE.md` §1).

## Rejected Alternatives

- **GraphQL (Option B)**: rejected for the external surface — the schema-federation problem across the Core/Product boundary would need to be solved before this even becomes usable for a multi-product platform, and REST's simpler auth/tooling story better serves unknown future third-party integrators.
- **RPC/tRPC/gRPC (Option C)**: rejected for the external surface — tRPC's tight client/server coupling is unsuitable for external, cross-language consumers; gRPC remains a candidate for internal service-to-service calls only, if and when the platform splits into multiple deployables, but is not adopted now.

## Future Migration / Extension Path

- An internal-only RPC mechanism (e.g., gRPC between deployables) could be introduced later purely for Core↔Product↔Control-Plane traffic without touching the external REST/OpenAPI contract, since the two surfaces are already required to be independent (`docs/API-ARCHITECTURE.md` §1).
- A future `v2` external API version is expected to coexist with `v1` for a defined deprecation window rather than replacing it in place — this deprecation discipline is part of this decision, not a later addendum.

## What Would Be Difficult to Change Later

Retrofitting versioning onto an API that shipped unversioned typically forces a breaking migration on whichever early consumers exist. This is why versioning is adopted from the very first route rather than deferred.

## Related

`docs/API-ARCHITECTURE.md`; `docs/ARCHITECTURE-DISCOVERY.md` §12.
