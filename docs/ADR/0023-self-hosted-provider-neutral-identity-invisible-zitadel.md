# ADR-0023: Self-Hosted, Provider-Neutral Identity with Invisible ZITADEL

**Status:** Draft
**Decision Type:** Architecture / Identity / Deployment
**Scope:** SaaS-OS
**Date:** 2026-09-23

---

## 1. Context

SaaS-OS currently implements authentication as a generic OpenID Connect relying party.

The current architecture:

```text
Product
   ↓
SaaS-OS Identity
   ↓
OIDC
   ↓
Configured Identity Provider
```

The current implementation is already provider-behavior-neutral:

* OIDC discovery is used instead of hardcoded provider endpoints.
* ID tokens are validated generically.
* Identity mapping uses `(issuer, subject)`.
* SaaS-OS creates and owns its own application session.
* SaaS-OS owns tenant membership and authorization.
* API keys and service accounts are independent credentials.
* The reference consumer does not depend directly on ZITADEL.

The current configuration names the provider as ZITADEL:

```text
ZITADEL_ISSUER_URL
ZITADEL_CLIENT_ID
ZITADEL_CLIENT_SECRET
```

and ADR-0005 records ZITADEL as the current OIDC provider with an intended future provider-swap path.

However, the current repository does not self-host ZITADEL.

A local development environment currently requires an already-running OIDC provider outside the SaaS-OS Docker topology.

The desired deployment model is cloud-independent:

```text
Own infrastructure
├── SaaS application
├── SaaS-OS
├── PostgreSQL
├── Redis
└── self-hosted identity provider
```

A mandatory dependency on ZITADEL Cloud is therefore explicitly undesirable.

---

## 2. Requirements

The identity architecture SHALL satisfy the following:

1. SaaS-OS MUST NOT require ZITADEL Cloud.
2. SaaS-OS MUST support self-hosted ZITADEL.
3. Local development SHOULD be possible without an external identity provider.
4. Products built on SaaS-OS MUST NOT directly integrate with ZITADEL.
5. ZITADEL MUST remain an implementation detail of the SaaS-OS identity infrastructure.
6. SaaS-OS authorization MUST remain independent from the identity provider.
7. Tenant membership and authorization MUST remain enforced by SaaS-OS.
8. API keys and service accounts MUST remain independent credential primitives.
9. The identity provider SHOULD be replaceable with another conformant OIDC provider.
10. Production deployments SHOULD be able to run entirely on infrastructure controlled by the SaaS operator.
11. ZITADEL MUST NOT require its own publicly exposed **host port** (never a raw port on the public interface); it MAY require its own publicly exposed **hostname** (verified in Phase 3 to be a hard requirement, not optional -- see S9's correction) provided that hostname is an operator-controlled subdomain of the product's own registrable domain, never a third-party or ZITADEL-branded one.
12. The product-facing login experience SHOULD remain on the product's own domain.
13. The architecture MUST NOT introduce a second authorization engine.
14. Existing `core/identity` functionality SHOULD be preserved rather than rewritten.

---

## 3. Decision

SaaS-OS will use a **provider-neutral identity boundary with self-hosted ZITADEL as the default self-hosted OIDC implementation**.

The conceptual architecture is:

```text
Product
   ↓
SaaS-OS Identity
   ↓
OIDC Provider Boundary
   ↓
ZITADEL
```

Products depend only on SaaS-OS identity functionality.

Products MUST NOT contain ZITADEL-specific authentication logic.

ZITADEL is infrastructure.

---

## 4. Authentication vs Authorization

The responsibilities remain explicitly separated.

### Identity provider

The identity provider is responsible for authentication and identity-provider capabilities such as:

* credential authentication
* MFA
* WebAuthn
* identity federation
* OIDC authorization
* ID-token issuance
* provider-side identity management

### SaaS-OS

SaaS-OS remains responsible for:

* application users
* external identity mapping
* application sessions
* tenant membership
* tenant context
* RBAC
* scoped roles
* delegation
* explicit deny
* service accounts
* API keys
* support access
* audit
* tenant lifecycle
* authorization decisions

The identity provider MUST NOT become an authorization bypass.

In particular:

```text
OIDC authentication
        ↓
SaaS-OS user
        ↓
SaaS-OS tenant membership
        ↓
SaaS-OS RBAC / delegation / deny
        ↓
authorization
```

Authorization MUST NOT be inferred solely from an OIDC token.

---

## 5. Identity Mapping

The canonical external identity remains:

```text
(issuer, subject)
```

Email address MUST NOT be used as the identity key.

This prevents collisions between identities that share an email address and distinguishes identical subjects issued by different providers.

SaaS-OS retains ownership of the internal user identity.

The intended mapping remains:

```text
OIDC issuer + subject
          ↓
external_identity
          ↓
SaaS-OS user
```

The identity provider's internal user identifier MUST NOT become the canonical SaaS-OS user identifier.

---

## 6. Application Sessions

After successful OIDC authentication:

```text
OIDC ID token
      ↓
validation
      ↓
SaaS-OS user resolution
      ↓
SaaS-OS session creation
      ↓
opaque application session cookie
```

The OIDC ID token is not persisted as the SaaS-OS session.

SaaS-OS continues to own the application session lifecycle.

This preserves the ability to change identity providers without redesigning the application's authorization/session model.

---

## 7. Provider Abstraction

The current OIDC implementation is already behaviorally generic, but provider neutrality is currently enforced primarily by convention.

A future implementation phase will introduce a thin provider-neutral configuration boundary analogous to existing provider abstractions such as:

* `BillingProvider`
* `EmailProvider`
* `SecretsProvider`

The abstraction SHOULD remain deliberately small.

It SHOULD NOT introduce unnecessary runtime polymorphism if only one provider is active per deployment.

The initial target is a generic configuration boundary:

```text
IdentityProviderConfig
        ↓
generic OIDC implementation
```

rather than:

```text
ZITADEL-specific identity engine
```

Provider-specific behavior MUST remain outside product code.

---

## 8. Self-Hosted ZITADEL

SaaS-OS will support a self-hosted ZITADEL deployment.

The intended production topology is:

```text
Internet
   │
   ▼
Caddy / reverse proxy
   │
   ├── SaaS application
   │
   └── identity path
          │
          ▼
      private ZITADEL
          │
          ▼
      ZITADEL PostgreSQL
```

ZITADEL SHOULD NOT expose a host port directly.

ZITADEL SHOULD reside on a private Docker network.

The public reverse proxy is responsible for controlled exposure.

---

## 9. Product-Domain Identity Exposure

**Corrected by the Phase 3 implementation (docs/ADR/0023-... Phase 3, `docker-compose.prod.yml`/`Caddyfile`) -- this section's original `/idp/*` path-prefix aspiration below has been verified against ZITADEL's own official reverse-proxy documentation and does not work; the corrected model follows.**

ZITADEL does not provide a supported arbitrary path-prefix deployment model. Its own fixed, root-relative route table (`/oauth/v2/*`, `/oidc/v1/*`, `/.well-known/openid-configuration`, `/ui/console`, `/management/v1/*`, `/debug/*`, and more added across versions) is not prefixable or rewritable, and ZITADEL's own official Caddy/NGINX/Traefik reverse-proxy examples all route it at the domain root of its own hostname -- never as a stripped subpath of a shared domain. A `https://app.example.com/idp/*` -> strip `/idp` -> forward-to-ZITADEL design, as originally proposed in this ADR, is therefore not implementable against ZITADEL as documented.

**The production topology instead uses an operator-controlled identity subdomain** of the same registrable domain as the product's own public domain -- e.g. `id.example.com` alongside `app.example.com` -- fronted by its own Caddy site block, routed to ZITADEL at the root (unmodified, matching ZITADEL's own supported shape exactly).

```text
https://app.example.com   -- the product (frontend + backend)
https://id.example.com    -- ZITADEL, operator-controlled subdomain of the same registrable domain
```

This keeps the browser on hostnames the operator controls throughout -- both `app.example.com` and `id.example.com` are the product's own infrastructure, never a ZITADEL-branded or third-party domain -- but **the browser's address bar does change host, not merely path, during the OIDC authorization-redirect leg.** This is a materially weaker guarantee than this section's original wording implied, and this ADR no longer claims otherwise.

Standard OIDC authorization-code authentication inherently involves a browser navigation to the authorization endpoint; that redirect cannot be eliminated without abandoning standards-based OIDC (which would forfeit the MFA/SSO/WebAuthn federation benefits ADR-0005 selected ZITADEL for). Given that, "invisible" in this ADR's title and throughout means:

> No ZITADEL branding, no third-party or vendor-owned hostname, no direct product-code dependency on ZITADEL, and no public ZITADEL host port -- **not** a literally single, unchanging hostname across the whole login flow, and not elimination of the OIDC authorization redirect itself.

SaaS-OS remains provider-neutral at the application layer regardless of this correction -- `OIDC_ISSUER_URL` (Phase 2, `core/identity/provider.py`) is the only thing that changes if a different OIDC-compliant provider, or a different subdomain, is configured; no application code encodes this ADR's own example hostnames.

The identity provider remains an operator/infrastructure concern.

---

## 10. Local Development

**CURRENT IMPLEMENTATION:** `zitadel`, `zitadel-db`, and `zitadel-bootstrap` are unconditional services in `docker-compose.yml` -- none of the three carries a Compose `profiles:` key. The ordinary local development workflow:

```text
docker compose up
```

already starts the full local identity stack alongside SaaS-OS, PostgreSQL, Redis, and the worker. There is currently no optional `--profile identity` flag; identity is not separable from the rest of the local Compose topology today.

Bootstrap (the `saas-os-local-identity` console script, `infra/local_identity/zitadel_bootstrap.py`, invoked by the `zitadel-bootstrap` service; `local-dev/bootstrap_zitadel.py` remains as a delegating compatibility entrypoint) is idempotent and deterministic as already documented in `docs/LOCAL-IDENTITY.md`: it lists existing project/application resources by name before creating them, so re-running `docker compose up` against an already-bootstrapped instance is safe and does not create duplicates.

The local identity environment is usable without ZITADEL Cloud.

A separate direct ZITADEL host port MAY be provided for local operator/developer administration if required, but this MUST NOT be treated as the production topology.

**FUTURE / OPTIONAL CONSIDERATION:** an opt-in `docker compose --profile identity up` split (identity services separated from the default `docker compose up` set) remains a possible future refinement if a need to run SaaS-OS locally without the identity stack emerges. This is not current behavior and is not required for this ADR's acceptance.

---

## 11. ZITADEL Database Isolation

ZITADEL SHOULD use an independently managed database boundary.

The preferred model is:

```text
SaaS-OS PostgreSQL
    └── SaaS-OS database

ZITADEL PostgreSQL
    └── ZITADEL database
```

or equivalent independent logical database isolation where operationally appropriate.

The reasons are:

* independent migration history
* independent upgrade cadence
* independent backup/restore
* reduced blast radius
* clearer ownership
* separation of failure domains

ZITADEL's schema MUST NOT be incorporated into the SaaS-OS Alembic migration history.

SaaS-OS migrations MUST NOT depend on ZITADEL migrations.

---

## 12. Production Self-Hosting

The target self-hosted production environment is:

```text
VPS / operator-controlled infrastructure
│
├── Caddy
├── SaaS application
├── SaaS worker
├── SaaS PostgreSQL
├── Redis
├── ZITADEL
└── ZITADEL PostgreSQL
```

No cloud identity provider is required.

Production operation MUST include explicit handling for:

* ZITADEL persistence
* ZITADEL PostgreSQL backups
* ZITADEL signing/master key persistence
* restore procedures
* upgrades
* health checks
* startup ordering
* TLS
* secrets
* disaster recovery

The existing SaaS-OS database backup mechanism does not automatically cover ZITADEL and MUST NOT be assumed to do so.

---

## 13. Provider Replacement

The architecture MUST preserve the possibility of replacing ZITADEL with another conformant OIDC provider.

The desired migration boundary is:

```text
Product
   ↓
SaaS-OS Identity
   ↓
OIDC
   ↓
Provider A
```

replaceable by:

```text
Product
   ↓
SaaS-OS Identity
   ↓
OIDC
   ↓
Provider B
```

Products MUST NOT require code changes merely because the configured OIDC provider changes.

Provider-specific operational configuration MAY change.

External identity mappings MAY require an explicit migration strategy when changing issuer/subject identity.

---

## 14. Explicit Non-Goals

This decision does NOT introduce:

* a custom authentication protocol
* a custom password store
* a new authorization engine
* ABAC
* ReBAC
* OpenFGA
* a new identity database owned by SaaS-OS
* direct product-to-ZITADEL integrations
* ZITADEL-specific authorization claims
* a ZITADEL SDK dependency
* a requirement for ZITADEL Cloud
* automatic multi-provider account linking
* refresh-token persistence in SaaS-OS

---

## 15. Known Limitations

### OIDC browser redirect

Standard OIDC authorization-code flow requires browser navigation to the provider authorization endpoint.

A true "zero browser visibility" design would require a fundamentally different authentication mechanism and would undermine the OIDC architecture.

The accepted target is therefore:

> same product-domain browser experience where practical, private provider networking, and complete product-code abstraction.

### JWKS/discovery caching

The current implementation caches discovery/JWKS information for the process lifetime.

A future production-hardening phase SHOULD define controlled refresh behavior for provider key rotation.

### Account linking

The schema permits multiple external identities per SaaS-OS user, but there is currently no user-facing identity-linking/unlinking workflow.

This is deferred until there is a concrete product requirement.

---

## 16. Implementation Plan

Implementation SHALL be performed as separate checkpointed phases.

### Phase 1 — Local Self-Hosted Identity

* self-hosted ZITADEL, as an unconditional local Compose service (§10) -- ordinary `docker compose up` starts it; no `--profile identity` split was implemented (an opt-in profile remains only a possible future/optional consideration, not part of this phase)
* dedicated ZITADEL PostgreSQL
* local bootstrap
* local development configuration
* no production topology changes

### Phase 2 — Provider-Neutral Identity Configuration

* generic identity-provider configuration boundary
* remove unnecessary ZITADEL-specific configuration naming from the application-facing abstraction
* preserve backward compatibility where appropriate
* update ADR-0005

### Phase 3 — Production Self-Hosted Identity

* private ZITADEL network
* reverse-proxy integration
* product-domain identity path
* ZITADEL external-domain configuration
* health checks
* startup dependencies
* persistent signing/master key handling

### Phase 4 — Identity Operations

* ZITADEL backup coverage
* restore procedure
* key rotation procedure
* upgrade procedure
* disaster recovery documentation

### Phase 5 — Optional Identity Linking

Only if a product requirement emerges:

* identity linking
* unlinking
* account recovery semantics
* migration between identity providers

No Phase 5 implementation is implied by this ADR.

---

## 17. Consequences

### Positive

* SaaS-OS can run without ZITADEL Cloud.
* Local development can become self-contained.
* Products remain provider-neutral.
* SaaS-OS remains the authorization authority.
* ZITADEL can remain entirely infrastructure-owned.
* Self-hosted VPS deployments become possible.
* Provider replacement remains architecturally feasible.
* Existing Core identity/session architecture can be preserved.

### Negative

* Self-hosting adds operational responsibility.
* ZITADEL becomes another persistent infrastructure component.
* ZITADEL requires its own upgrade and backup lifecycle.
* Product-domain proxying adds reverse-proxy complexity.
* Identity-provider availability becomes an operator-managed dependency.
* Full elimination of browser-side OIDC provider navigation is not possible with standard redirect-based OIDC.

---

## 18. Relationship to ADR-0005

This ADR is an extension of the existing ZITADEL/OIDC decision.

ADR-0005's provider-portability intent remains valid.

This ADR adds the deployment requirement that:

> ZITADEL MUST be usable as a self-hosted infrastructure component and MUST NOT become a mandatory cloud dependency.

It also formalizes the stronger product-boundary rule:

> Products consume SaaS-OS Identity; products do not consume ZITADEL directly.

---

## 19. Status

**DRAFT — NOT YET ACCEPTED**

Acceptance requires review of:

* local ZITADEL Compose topology
* provider-neutral configuration boundary
* production reverse-proxy strategy
* ZITADEL persistence and backup model
* identity-provider operational lifecycle
* the downstream product contract and compatibility implications (below)

No implementation is authorized by this draft alone.

### Downstream product contract and compatibility

SaaS-OS is consumed by product repositories (e.g. Marketstack) that pin a specific SaaS-OS commit. Acceptance of this ADR also requires explicit agreement on the following, as **ARCHITECTURAL CONTRACT** (binding on any product consuming SaaS-OS identity) versus **CURRENT IMPLEMENTATION** (what SaaS-OS itself provides today):

**Application-facing identity configuration (ARCHITECTURAL CONTRACT):**

* `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET` are the canonical, stable, application-facing identity configuration names a downstream product's SaaS-OS-backed backend reads.
* `ZITADEL_ISSUER_URL`, `ZITADEL_CLIENT_ID`, and `ZITADEL_CLIENT_SECRET` are **not** functional compatibility aliases for the above -- `core/identity` no longer reads them for their value under any circumstance. A deployment that sets only the legacy names does not receive equivalent behavior; it fails configuration validation. No migration shim, dual-read fallback, or deprecation window exists for these names, and this ADR does not introduce one.
* A product upgrading its SaaS-OS pin across this rename must update its own `.env`/`.env.example` and deployment configuration to the `OIDC_*` names as a required, non-optional step of that upgrade.

**Provider boundary (ARCHITECTURAL CONTRACT):**

* Downstream products consume identity exclusively through SaaS-OS's provider-neutral boundary (`core/identity`, `api/auth/*`) -- never ZITADEL directly.
* Downstream products MUST NOT import a ZITADEL SDK, call ZITADEL's Management/Admin APIs, or otherwise embed ZITADEL-specific logic in product code.
* This is confirmed as the existing behavior of the reference consumer and is a binding expectation for any other product built on SaaS-OS, consistent with Requirement 4 in §2.

**Local development (CURRENT IMPLEMENTATION):**

* SaaS-OS provides its **own** local self-hosted ZITADEL Compose topology (§10) for developing SaaS-OS itself.
* *Amendment (local identity tooling generalization):* the local bootstrap is now shipped in the `saas-os` package as the product-neutral `saas-os-local-identity` console script, parameterized by `OIDC_LOCAL_PROJECT_NAME`, `OIDC_LOCAL_APPLICATION_NAME`, and the product's own `OIDC_REDIRECT_URI` (defaults preserve SaaS-OS's own `saas-os`/`saas-os-backend`). A downstream product runs it from its installed SaaS-OS dependency; it never copies SaaS-OS source and never calls ZITADEL's APIs from its own code. `docs/LOCAL-IDENTITY.md` ("Downstream product development") is the supported integration path. This is development tooling only and changes nothing in the production contract below.
* SaaS-OS still does **not** provide an importable/reusable Compose fragment: a downstream product declares the ZITADEL services in its own Compose file (third-party images plus configuration, owned by the product), following `docs/LOCAL-IDENTITY.md`.

**Production topology (distinguishing reference architecture from mandatory contract):**

* This ADR's production topology (§8, §12) is a **reference architecture** SaaS-OS itself implements and validates (`docker-compose.prod.yml`, `Caddyfile`, `scripts/check-docker-prod.sh`) -- it demonstrates that self-hosted, cloud-independent identity is achievable and documents one concrete way to do it.
* This ADR does **not** establish a mandatory downstream implementation contract requiring every product built on SaaS-OS to independently reproduce this exact production Compose/network/reverse-proxy configuration. A downstream product remains free to design its own production identity deployment, subject only to the architectural contract above (provider-neutral consumption, canonical `OIDC_*` configuration, no direct ZITADEL coupling in product code).
