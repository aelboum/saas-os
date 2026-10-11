# ADR-0040: Reusable HTTP platform capabilities

Status: Accepted (2026-10-11) — Option B; stage 1 implemented as amended below; stages 2 and 3 remain blocked on their prerequisites
Date: 2026-10-11
Supersedes / Superseded by: —

## Context

A product built on SaaS OS receives health routes, OIDC auth routes and an ingress chain. Every other HTTP endpoint — including ones that are identical for every product, such as "list the members of my organization" or "create an API key" — has to be written by the product on top of Core functions. The inventory is `docs/architecture/HTTP-CAPABILITY-MATRIX.md`.

The cost is not only repetition. Member, invitation, API-key and webhook endpoints return one-time secrets, enforce non-enumeration and decide which reads are gated. Each product re-deriving that is the "ad hoc, per-team discipline" ADR-0017 rejected for the ingress chain itself.

Existing documents pull in different directions (matrix §5):

- ADR-0017 lists what SaaS OS may expose as reusable API components; capability routes are not on the list.
- `docs/API-ARCHITECTURE.md` assigns "Core capability routes (billing, api-keys, webhooks, feature-flags, audit-log query)" to the Core modules.
- Every Core module's `__init__` says it owns no HTTP surface, and `api/__init__.py` defers capability routes to "a future phase with an actual tested need".

No product exists, so there is no "actual tested need" in the sense `api/__init__.py` asks for. This ADR therefore does two things: it settles the ownership rule now, because that is a contract question a first product will hit on day one; and it stages implementation so that nothing security-sensitive is built ahead of its prerequisite.

The matrix identifies four gaps in what the ingress chain can express: **G1** no platform/operator authority over HTTP, **G2** no route policy for an authenticated non-member, **G3** no machine (API-key) authentication, **G4** no inbound provider-event ledger.

## Options Considered

### Option A — Status quo: products write every capability route
- Advantages: no new public contract; nothing to version; fully consistent with ADR-0017 as written.
- Disadvantages: every product re-implements the same security-sensitive endpoints; the first product pays the whole cost; no shared place for the one-time-secret and non-enumeration rules.

### Option B — SaaS OS ships opt-in capability routers for the capabilities that are generic, already authorized in Core and expressible by the existing chain
A product mounts each router explicitly (`app.include_router(members_router)`); `build_platform_app` mounts none of them.
- Advantages: reuse where the endpoint is the same for every product; the product keeps composition (ADR-0017's actual requirement); each router is a small, reviewable unit; nothing in the set needs a new authority model.
- Disadvantages: request and response shapes become public contract under `/v1`; SaaS OS has to maintain them; a product that wants a different shape writes its own anyway.

### Option C — SaaS OS ships a complete management API, mounted by default
- Advantages: a product gets an administration API with no work.
- Disadvantages: contradicts ADR-0017 (a consumer forced to take SaaS OS's application surface); needs G1–G4 solved first; puts tenant lifecycle and flag control on the network.

### Option D — A separate management service
- Advantages: one API for many products.
- Disadvantages: ADR-0015 already rejected a shared network runtime (its Option F), for reasons that still hold.

## Recommendation

**Option B, staged.** The rule that decides ownership:

> A capability gets a platform router when **all** of these hold: it means the same thing in every product; its authorization and audit already live inside the Core function; it is tenant-scoped; and the existing ingress chain can express its caller. Otherwise it stays with the product, or stays an operator command.

Applied to the matrix:

| Stage | Routers | Preconditions |
|---|---|---|
| **1 — fits today** | members and role assignment; invitations (create, list, revoke); own API keys and service accounts with their keys; outbound webhook subscriptions; plan-catalog read and entitlements read | A read permission for each currently ungated read (members, invitations, API keys, webhook subscriptions). One-time secrets returned exactly once, never logged, never stored in an idempotency replay. |
| **2 — needs a decision first** | invitation accept (G2); API-key request authentication (G3) | G2: a third route policy, "authenticated, not necessarily a member", and an explicit ruling on whether the accepting identity's email must match the invited one. G3: its own ADR — credential precedence against session cookies, per-key rate limiting, how a service-account principal flows through `RequestContext`, which routes accept a key. |
| **3 — needs Core work first** | inbound billing-provider webhook (G4) | The provider-event ledger and handler deferred in ADR-0029. |
| **Never a route** | tenant create/move/lifecycle/purge; identity erasure; flag catalog and tenant overrides; first-tenant bootstrap | Stay operator commands until a platform-authority model exists (G1), which is not proposed here. |
| **Product** | sign-up; checkout and subscription management; merchant and payer setup; usage ingestion and reports; anything domain-specific | — |

Contract rules for any router that is built:

1. **Opt-in.** Never mounted by `build_platform_app`. A product that mounts none is unaffected.
2. **`/v1/tenants/{tenant_id}/…`**, typed response models, never an ORM entity (the `tenant_status` precedent).
3. **Exactly one route policy each** (ADR-0030); no public route in stage 1.
4. **No authorization logic in the router.** The Core function's own `authorize_caller` stays the decision; the route's `require_permission` is the same permission, not a second policy.
5. **Additive evolution inside `/v1`**; a breaking change needs `/v2` (ADR-0006).
6. **`api/v1/tenant_status.py`** is classified as a stage-1 platform router, closing ADR-0017's open item; it stays unmounted by default.
7. The conflict between `docs/API-ARCHITECTURE.md:17` and the Core modules is resolved in favor of the modules: routers live in `api/v1/`, Core owns no HTTP surface.

## Decision

**Accepted by the repository owner on 2026-10-11: Option B — opt-in capability routers, with explicit registration and authorization.** The owner's priority order for stage 1 was: tenant and membership management, invitations, API-key management, billing and subscription lifecycle, usage and entitlement visibility; webhooks and feature-flag administration are to be assessed separately and not exposed merely because an implementation exists.

That priority list is wider than the Recommendation above in two places (tenant management; billing lifecycle). The owner also confirmed, on the same day, the following scoping of it, which is what was built:

| Capability | Decision | Reason |
|---|---|---|
| Membership: list, suspend, reactivate, revoke | **Implemented** (`saas_os/api/v1/members.py`) | Authorized and audited in Core |
| Tenant lifecycle: create, move, suspend, delete, purge | **Not exposed — blocked (G1)** | The Core functions have no authorization and there is no platform-wide permission model; a route would be their only gate. That is a new security-boundary decision |
| Invitations: create, list, revoke | **Implemented** (`invitations.py`) | Authorized and audited in Core |
| Invitation accept | **Not exposed — blocked (G2)** | Needs a non-member route policy and a ruling on email match |
| A member's own API keys: create, list, rotate, revoke | **Implemented** (`api_keys.py`) | Core confines each mutation to the owner or a permission |
| Other principals' keys; service accounts | Not exposed | Outside the smallest coherent set |
| API-key request authentication | **Not exposed — blocked (G3)** | A second way to be a principal; needs its own ADR |
| Billing: entitlements, eligible plans, subscribe, cancel, payer subscription reads | **Implemented** (`billing.py`, a factory bound to a `BillingProvider`) | Every invariant is enforced in Core; the route adds none |
| Catalog management, merchant and billing-account setup, seller views, plan change, invoices | Not exposed | Product- or operator-specific |
| Inbound billing-provider webhook | **Not exposed — blocked (G4)** | Needs the provider-event ledger ADR-0029 defers |
| Usage: the tenant's own report | **Implemented** (`usage.py`) | Authorized in Core |
| Usage ingestion over HTTP | Not exposed | A client asserting its own consumption is a metering bypass |
| Outbound webhook subscriptions | **Assessed, not exposed** | Authorized in Core and expressible by the chain, so it qualifies technically; held back because `http://` targets are still accepted (ADR-0035) and there is no secret rotation or disable, which a public route would make more exposed |
| Feature-flag administration | **Assessed, not exposed** | No authorization and no permission exists in Core for flags; a tenant override changes what a tenant may do (the self-learning kill switch is a flag). Operator-only until an authority model exists |

Contract rules 1–7 of the Recommendation are adopted. `saas_os/api/v1/tenant_status.py` stays unmounted by default and is classified as a platform router.

**New permissions.** Three, each because the Core function behind the route has no authorization of its own (`saas_os/api/v1/permissions.py`):

- `membership:read` and `invitation:read` — the list functions take no caller;
- `api_key:self_manage` — Core lets any active member issue a key to themselves. Over HTTP that is default-deny: a tenant grants the permission to the roles whose members may hold keys. HTTP is deliberately stricter than Core here, never looser.

All three are on authority resources, so a support-access session can never satisfy them. No existing permission, Core rule or access control was changed.

## Security preconditions (apply to whatever is approved)

- Each router ships with the denial matrix already used for `tenant_status` and the reference consumer route: no credential, non-member, member without permission, suspended tenant, foreign tenant in the path, foreign object id.
- Cross-tenant, sibling and ancestor/descendant cases are tested per router, with a negative control that removes the permission dependency and shows the test failing.
- Responses that carry a one-time secret are excluded from logs and from any cached or replayed response.
- List endpoints are bounded and paginated.
- Support-access sessions cannot reach the authority resources (`core/rbac/authorization.py` `AUTHORITY_RESOURCES`); the routers must not provide a path around that.

## What Would Be Difficult to Change Later

Request and response shapes under `/v1` become contract the moment one product's frontend calls them. Choosing which reads are gated, and by which permission names, is equally sticky: a product will have granted those permissions to roles in its tenants' data. API-key authentication (stage 2) is the hardest to reverse of everything listed, because it creates a second way to be a principal on every route that accepts it.

## Related

`docs/architecture/HTTP-CAPABILITY-MATRIX.md` (evidence); ADR-0006 (API style and versioning); ADR-0015 (rejected shared network runtime); ADR-0017 (application boundary; its unclassified `tenant_status` route); ADR-0029 (billing parties; deferred provider-event ingestion; product-owned usage-report routes); ADR-0030 (route policy); ADR-0031 (typed callers and same-transaction audit); ADR-0035 (webhook subscription authority); ADR-0037 (usage semantics); `docs/API-ARCHITECTURE.md`; `docs/P-ROADMAP.md` P4.

## Implementation Note (2026-10-11)

- **Routers**: `saas_os/api/v1/{members,invitations,api_keys,billing,usage}.py`, exported from `saas_os.api.v1`. 18 routes. None is mounted by `build_platform_app()` or by this repository's own `saas_os/api/main.py`; a product registers each one with `app.include_router(...)`. `build_billing_router(provider=...)` binds the billing provider when the router is built; nothing in a request can select one.
- **One policy per route**: each route's policy is `require_permission(resource, action)` with the pair listed in `saas_os/api/v1/permissions.py`. Where Core enforces a permission, the route uses the same pair. `register_capability_permissions()` registers the catalog entries; it grants nothing.
- **No decision in a router**: handlers read the tenant from the verified `RequestContext` (never from the path), call Core with `UserCaller(context.actor_id)`, and map Core's typed errors to fixed responses. They import neither the database layer nor `can()`.
- **Non-enumeration**: a foreign tenant in the path is the ingress chain's `tenant not found.`; a foreign or missing object id is one 404 per resource; Core's own refusal after the route's gate is the generic 403.
- **One-time secrets**: the invitation token and the API key appear only in `CreatedInvitationResponse.token` and `IssuedApiKeyResponse.key`. `token_hash`, `key_hash` and `provider_subscription_id` are in no response model.
- **Lists** are bounded (`limit` ≤ 500, `offset`).
- **New error helpers**: `saas_os.api.errors.conflict()` (409) and `invalid_request()` (400), each with a fixed literal detail.
- **Tests**: `tests/api/v1/test_capability_routers_unit.py` (25, hermetic) pins the exact route set, the one permission per route, opt-in mounting, response-model contents, that routers decide nothing, and that the guide's registration example names real routers. `tests/api/v1/test_capability_routers_integration.py` (31, real PostgreSQL and Redis) runs, for every one of the 18 routes: no credential (401), non-member (404), member with no permission (403), member with every capability permission except the route's own (403), member with only the route's permission (the exact status Core answers), and another tenant's administrator (404). Then: per-router flows; cross-tenant object ids; one-time secrets against the stored hashes; billing's dual authority, payer substitution, idempotent replay, a reused key with a different valid request (409), and the payer read model after its outbox consumer has actually run; the specific `membership.suspend` audit row and the `api.access_denied` row; a suspended tenant (404 for its own administrator); a parent tenant's SELF-scoped administrator against a child tenant (404, both directions); control characters in request fields; and an invalid `Idempotency-Key` from an unauthorized caller (401/403, not 400).
- **Negative control** (run by hand, 2026-10-11, not an in-tree test): with the members list gated by `membership:suspend` instead of `membership:read`, `test_denial_matrix[GET members]` and the contract test both fail; restored byte for byte, both pass. The in-tree control is the matrix's own all-but-one / only-this-one pair.
- **Independent review** (a separate agent, on the diff): no CRITICAL or HIGH finding; no cross-tenant read or write, no secret in any response, no Core check weakened. Fixed: several assertions that were weaker than their comments (a status accepted from two values, a payer-subscription check that passed on an empty list, an audit check that counted any row); a plan-existence oracle on subscribe (an unknown plan and an ineligible one returned different 404 details — now one, `plan or billing account not found.`); `TenantInaccessibleError` unmapped (a tenant suspended between the gate and the Core call was a 500, now the chain's 404); a bare `except ValueError` in the usage route; control characters reaching PostgreSQL as a 500; the `Idempotency-Key` header examined before authentication.
- **Not done**: no OpenAPI document is committed (FastAPI generates it per application, outside production); no rate limit beyond the chain's per-tenant, per-path limit; no service-account or cross-principal key management; the scaffold does not mount a capability router.

## Security findings from the review

1. ~~MEDIUM — no last-administrator guard on membership suspend/revoke~~ — **resolved by ADR-0043** (2026-10-11): one invariant, enforced in Core around every change that can remove administrative authority, in the tenant or from an ancestor, including tenant move and suspension; `409` from the route. Remaining limits are in ADR-0043.
2. ~~MEDIUM — cross-site request forgery on cookie-authenticated unsafe methods~~ — **resolved by ADR-0044** (2026-10-11): an unsafe-method request authenticated by the session cookie must carry the application's own `Origin`; Bearer clients are exempt.
3. **LOW — list routes page in Python.** Core's list functions return every row; the routes slice afterwards. `GET api-keys` loads every key of the tenant (revoked and rotated rows are never deleted), and `GET billing/plans` evaluates eligibility for every active plan in the deployment. Bounded responses, unbounded work. Fix belongs in Core (`limit`/`offset` in the queries).
4. **LOW — API keys issued over HTTP never expire** (`expires_at` is not exposed), and a key outlives its owner's membership suspension, because `validate_api_key` does not check membership. Harmless while API-key request authentication (G3) is not built; it must be settled with G3.
5. **Not tested**: a support-access session against these routes (Core's exclusion by authority resource is covered by Core's own tests, not by a route test); a service-account-owned key against the own-key routes; an ancestor's SUBTREE-scoped role, which Core honours by design.

## Decisions needed for each deferred route group

None of these has a route, and none is added without its decision. Each entry says what Core already provides, what is missing, and the question to answer.

### Tenant lifecycle (create, move, suspend, reactivate, delete, purge) — gap G1

- **Exists**: `saas_os.core.tenancy.create_tenant`, `move_tenant`, `transition_tenant_status`, `purge_tenant`; the operator command `python -m saas_os.api.tenant_bootstrap`.
- **Missing**: any authorization. These functions take no caller and call no `can()`; `core.tenants` is not tenant-scoped; `saas_os.core.rbac.can()` is tenant-scoped by construction, so it cannot express "may create a tenant" or "may suspend any tenant".
- **Decide**:
  1. Is there a platform operator principal over HTTP at all, or do these stay operator commands?
  2. If yes: how is it represented — a permission evaluated at the designated platform tenant (`PLATFORM_TENANT_ID`), a separate operator credential, or a distinct authority type next to `UserCaller`?
  3. Is self-service "create my organization" a platform route (then: who may call it, with what abuse controls — verification, rate limit, quota) or a product flow built on `create_tenant` (the current recommendation)?
  4. May a tenant's own administrator suspend or delete their tenant, and is purge ever reachable from a request path (today the import-linter comment says never)?
  5. Core must gain caller-taking, audited variants of these functions before any route — in which phase?

### Invitation acceptance — gap G2

- **Exists**: `saas_os.core.identity.accept_invitation(raw_token, tenant_id, caller=UserCaller)`; the token is the credential; all failures are one error type.
- **Missing**: a route policy for "authenticated, not a member of this tenant" (the only tenant-scoped policy requires membership), and the email rule Core leaves to the ingress layer.
- **Decide**:
  1. Add a third route policy kind, or let accept depend on `get_current_actor` (authenticated) with the tenant taken from the invitation rather than the path?
  2. Must the accepting identity's **verified** email equal `invited_email`? `core.users` stores no email, so this means trusting an identity-provider claim: which claim, and what if the provider does not assert `email_verified`?
  3. Rate limiting for a token-guessing surface that has no tenant context yet: keyed by client address like `/auth/*`, by actor, or both?
  4. Should the route reveal the tenant's name before acceptance?

### API-key request authentication — gap G3

- **Exists**: `saas_os.core.api_keys.validate_api_key(raw_key)`, which authenticates only; `ServiceAccountCaller`; `can()` with `actor_type=SERVICE_ACCOUNT`.
- **Missing**: everything at ingress — `get_current_actor()` accepts session credentials only, `RequestContext` carries a user id, and billing authorization does not accept `ServiceAccountCaller`.
- **Decide**:
  1. Credential precedence and transport: a distinct scheme or header for keys, or `Authorization: Bearer` shared with sessions (then: how are the two told apart without a lookup on every request)?
  2. Which routes accept a key: all permission-gated routes, an allow-list, or never the authority resources (membership, invitation, API key management)?
  3. How a machine principal flows through `RequestContext` and into Core callers (user key → `UserCaller`? service-account key → `ServiceAccountCaller`), and what billing does with it.
  4. Per-key rate limiting, which `docs/API-ARCHITECTURE.md` already specifies.
  5. Key lifetime: keys issued over HTTP never expire today, and a key outlives its owner's membership suspension because `validate_api_key` does not check membership. Both must be settled here: mandatory or maximum `expires_at`, and whether validation checks membership status.
  6. ADR-0044 exempts header credentials from the origin check on the grounds that a browser cannot be made to send them cross-origin; confirm that holds for the chosen key transport.

### Inbound billing-provider webhook — gap G4

- **Exists**: `saas_os.core.billing.stripe_provider.verify_stripe_webhook_signature(payload, signature_header, webhook_secret)`, returning the SDK's own `stripe.Event`; `reconcile_subscription_status`; provider references (`core.billing_provider_refs`).
- **Missing**: the provider-event ledger and handler ADR-0029 defers to Billing Foundation v2 Phase 6 — no deduplication table, no mapping from event type to a Core mutation, no provider-neutral event type.
- **Decide**:
  1. Schedule that phase: the ledger schema (provider, event id, received/processed state), replay and ordering semantics, and which event types change which subscription state.
  2. The route's policy: it is necessarily public and authenticated by signature over the raw body — the stated reason ADR-0030 requires, how the raw body is preserved through FastAPI, and the rate limit.
  3. Provider neutrality: one route per provider adapter, or one route with a provider path segment; and a provider-neutral event type instead of `stripe.Event` (ADR-0008's recorded violation).
  4. Which system authority the handler runs under (`SystemAuthority.BILLING_OPERATIONS`), and tenant resolution from a provider reference rather than from the request.
  5. Whether this route ships only with the `saas-os[stripe]` extra (ADR-0041).
