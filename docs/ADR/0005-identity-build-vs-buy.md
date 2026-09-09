# ADR-0005: Identity — build vs. buy

Status: Accepted
Date: 2026-09-06
Supersedes / Superseded by: —

## Context

`core/identity` owns authentication for the entire platform (`docs/SECURITY.md` §2). This is security-critical, high-effort-to-get-right infrastructure (credential storage, session management, MFA, SSO/SAML protocol compliance).

## Options Considered

### Option A — Build in-house
- Advantages: full control; no per-MAU vendor cost; no external dependency for a security-critical path
- Disadvantages: real, ongoing security burden; SSO/SAML/SCIM protocol compliance is substantial effort to build and maintain correctly; higher risk of subtle vulnerabilities in a domain with many known footguns

### Option B — Third-party managed identity provider (Auth0, Clerk, WorkOS)
- Advantages: offloads security-critical code to a specialist; fast to ship; enterprise features (SSO, SCIM) often available off the shelf
- Disadvantages: per-MAU vendor cost; proprietary integration surface risks coupling beyond the OIDC standard; data residency/self-hosting not available

### Option C — ZITADEL as external Identity Provider via OIDC
- Advantages: offloads credential storage, MFA, and SSO/SAML protocol compliance to a specialist system; open-source and self-hostable (control over data residency and cost as the platform scales); integrates via the standard OIDC protocol rather than a proprietary SDK, which keeps the platform's dependency at the protocol layer rather than the vendor layer; has native support for organization-like tenant structures, which maps naturally onto this platform's tenant model
- Disadvantages: still an external system to operate (self-hosted) or depend on (managed); the platform's `core/identity` must do real integration work (OIDC relying-party logic, claim mapping) rather than getting a full drop-in SDK

## Recommendation

Option C.

## Decision

**Accepted.** ZITADEL is the platform's external Identity Provider, integrated via standard OIDC. This changes the shape of `docs/SECURITY.md` §2 and `core/identity`'s scope:

- **Authentication mechanism (credential verification, MFA, password/SSO handling) is delegated to ZITADEL.** The platform does not store passwords or implement its own login form logic — it redirects to ZITADEL's OIDC flow and receives back a verified identity token.
- **`core/identity` owns everything after that handshake**: OIDC relying-party integration (token/claim validation), mapping the external OIDC `sub` claim to the platform's canonical `user_id`, platform-level session/token issuance for subsequent requests, and org-membership linkage to `core/tenancy`.
- **`core/rbac` (a separate module, unaffected by this decision) owns all application-level authorization and permissions.** ZITADEL is a source of *authenticated identity*, not of platform permissions — role/permission assignment, policy evaluation, and entitlement checks remain entirely the platform's own, custom logic. The platform does not delegate authorization to the IdP, even though ZITADEL itself has some authorization-adjacent features.
- Machine identities (API keys, AI Control Plane agents) are **not** authenticated through ZITADEL's human-user OIDC login flow. They are issued and verified through a separate mechanism inside `core/identity` (see `docs/AI-CONTROL-PLANE.md` §7), resolving to the same identity-context shape so `core/rbac` does not need to special-case human vs. machine callers.

## Rejected Alternatives

- **Build in-house (Option A)**: rejected — the security burden of correctly implementing credential storage, MFA, and SSO/SAML compliance is not justified when a specialist, self-hostable, standards-based alternative exists.
- **Auth0 / Clerk / WorkOS (Option B)**: rejected as the primary choice — these are strong options but were passed over in favor of ZITADEL's combination of self-hostability (data residency/cost control) and native OIDC-first, organization-aware design. This is not a judgment that Option B is unsuitable in general, only that Option C better fits this platform's constraints.

## Future Migration / Extension Path

Because integration happens at the OIDC protocol layer, `core/identity`'s relying-party logic must be written against standard OIDC claims and flows, not ZITADEL-proprietary APIs, wherever a choice exists. This means a future swap to a different OIDC-compliant IdP (self-hosted or managed) is a configuration and adapter change within `core/identity`, not a platform-wide rewrite — provided this discipline is followed from the first implementation.

## What Would Be Difficult to Change Later

The user↔org cardinality (`docs/MULTI-TENANCY.md` §1) and the canonical `user_id` scheme are referenced by every other module (billing seats, RBAC, audit logs) and are independent of which IdP sits behind authentication — these remain the truly hard-to-change elements, not the IdP choice itself, provided the OIDC-standard integration discipline above is maintained.

## Related

`docs/SECURITY.md` §2; `docs/MULTI-TENANCY.md` §1; `docs/AI-CONTROL-PLANE.md` §7; `docs/ARCHITECTURE-DISCOVERY.md` §10.
