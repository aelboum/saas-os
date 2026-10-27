# HTTP capability matrix

Status: evidence base for ADR-0040 (Accepted 2026-10-11). The "Proposed owner" columns below are the pre-decision inventory; what was decided and built is the table in ADR-0040's Decision. Module paths were updated for the `saas_os` root (ADR-0038). Inventory taken at commit `4fccc93`, 2026-10-11 (docs/P-ROADMAP.md, P4). This document is the inventory; it adds no route.

## 1. What is exposed over HTTP today

| Route | Module | Mounted by `build_platform_app` |
|---|---|---|
| `GET /healthz`, `GET /readyz` | `saas_os/api/health.py` | yes |
| `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`, `GET /auth/me` | `saas_os/api/auth/routes.py` | yes |
| `GET /v1/tenants/{tenant_id}/status` | `saas_os/api/v1/tenant_status.py` | no (ADR-0017 leaves it unclassified) |

Everything else in the eight areas below is a Python function with no route.

## 2. What the ingress chain can and cannot express

`saas_os.api.dependencies.require_permission(resource, action)` authenticates a **session** (bearer header or cookie), resolves a tenant the caller **is a member of**, rate-limits per tenant and evaluates one RBAC permission.

Three kinds of caller do not fit it, and each blocks part of the matrix:

| Gap | Blocks |
|---|---|
| **G1 — no platform/operator authority over HTTP.** There is no platform-wide permission model (`saas_os/core/identity/erasure.py:86-88`); `saas_os.core.rbac.can()` is tenant-scoped. | Creating, listing, moving, suspending and purging tenants; creating feature flags. |
| **G2 — no non-member route policy.** *Closed by ADR-0046 (2026-10-14).* | Accepting an invitation: the accepting user is by definition not yet a member. |
| **G3 — no machine authentication.** *Closed by ADR-0047 (2026-10-14): a route opts in with `require_permission(..., api_key=True)` and then accepts `X-API-Key`. The rest of this row is the analysis as it was written.* API-key HTTP authentication is an explicit non-goal (`saas_os/api/dependencies.py:35-43`, `saas_os/api/__init__.py:45-46`). `saas_os.core.api_keys.validate_api_key()` exists and authenticates, but nothing calls it at ingress. | Any server-to-server use of every route below, and usage ingestion in particular. |
| **G4 — no inbound provider-event ledger.** *Closed by ADR-0048 (2026-10-15): `build_stripe_billing_events_router()` serves `POST /v1/billing/providers/stripe/events` over the ledger `core.billing_provider_events`. The rest of this row is the analysis as it was written.* `verify_stripe_webhook_signature()` exists (`saas_os/core/billing/stripe_provider.py:158`), but there is no event handler and no deduplication table for a route to call; provider-event ingestion is deferred to Billing Foundation v2 Phase 6 (ADR-0029, roadmap). | An inbound billing webhook route. |

## 3. Matrix

Columns: **Core authorization** — how the function is authorized today, independent of any route. **Fits chain** — whether `require_permission` can front it as it is. **Secret** — whether the response would carry a value shown once. **Proposed owner** — the recommendation ADR-0040 asks to have confirmed: *Platform* (a reusable router shipped by SaaS OS, opt-in), *Product* (stays product-written), *Operator* (CLI only, no route).

### 3.1 Tenants — `saas_os/core/tenancy/service.py`

| Capability | Function | Core authorization | Fits chain | Secret | Proposed owner |
|---|---|---|---|---|---|
| Create tenant | `create_tenant` :247 | none — trusts caller | no (G1) | — | Operator |
| Move in hierarchy | `move_tenant` :317 | none | no (G1) | — | Operator |
| Lifecycle transition | `transition_tenant_status` :797 | none; `actor_user_id` is attribution only | no (G1) | — | Operator |
| Purge | `purge_tenant` :1013 | none; documented "never a live request path" (`pyproject.toml:573-582`) | no | — | Operator |
| Read own tenant | `get_tenant` :509 | none | yes | — | Platform (already exists as `tenant_status`) |
| Find by name / list open | `find_tenants_by_name` :226, `list_open_tenant_ids` :492 | none; enumerates across tenants | no (G1) | — | Operator |

Tenancy functions take no caller and call no `can()`. A route would be their only gate. Self-service sign-up ("create my organization") is a product flow with product-specific rules (plan, verification, abuse controls) and is not proposed for the platform.

### 3.2 Members — `saas_os/core/identity/service.py`, `saas_os/core/rbac/service.py`

| Capability | Function | Core authorization | Fits chain | Secret | Proposed owner |
|---|---|---|---|---|---|
| List members | `list_tenant_members` :356 | ungated read | yes — needs a new read permission | — | Platform |
| Add member directly | `add_tenant_membership` :298 | `membership:create` or provisioning system caller | yes | — | Platform |
| Suspend / reactivate / revoke | :650 / :670 / :696 | `membership:suspend\|reactivate\|revoke` | yes | — | Platform |
| Assign / remove role | `saas_os.core.rbac.assign_role`, `remove_role` | `membership_role:create` etc. | yes | — | Platform |
| Erase a user's identity | `saas_os.core.identity.erasure.erase_user_identity` | none; cross-tenant | forbidden to `api` by import-linter contract | — | Operator |

Mutations are authorized and audited inside the service, in the mutation's own transaction (ADR-0031). The reads are not gated in Core; a route must add the gate.

### 3.3 Invitations — `saas_os/core/identity/service.py`

| Capability | Function | Core authorization | Fits chain | Secret | Proposed owner |
|---|---|---|---|---|---|
| Create | `create_invitation` :750 | `invitation:create` | yes | **yes — raw token returned once** | Platform |
| List / get | :859 / :840 | ungated read | yes — needs a read permission | — | Platform |
| Revoke | `revoke_invitation` :871 | `invitation:revoke` | yes | — | Platform |
| Accept | `accept_invitation` | the token is the credential; caller must be an active user; bound to the verified email when given | **yes, since ADR-0046** (`authenticated`) | — | Platform: `invitation_acceptance_router` |

*Closed by ADR-0046 (2026-10-14): accept is served by `invitation_acceptance_router`, rate limited per user, and Core compares the session's verified email with the invited one when the route passes it. The paragraph below is the analysis as it was written.* Accept is a token-guessing surface and needs its own rate limit. Core deliberately does not check that the accepting identity's email matches the invited email — "that correspondence is Phase 8 ingress-layer's concern" (`saas_os/core/identity/service.py:1006-1010`). A route must decide that policy explicitly; it is a security decision, not an implementation detail. Delivering the invitation (email with a link into the product's UI) is product-specific.

### 3.4 API keys and service accounts — `saas_os/core/api_keys/service.py`, `saas_os/core/identity/service.py`

| Capability | Function | Core authorization | Fits chain | Secret | Proposed owner |
|---|---|---|---|---|---|
| Create own key | `create_api_key` :146 | self-issue; active member | yes | **yes — plaintext once** | Platform |
| Rotate | `rotate_api_key` :628 | own key, else `api_key:rotate` | yes | **yes** | Platform |
| Revoke | `revoke_api_key` :570 | own key, else `api_key:revoke` | yes | — | Platform |
| List / get | :473 / :462 | ungated read | yes — must filter to own keys or require a permission | — | Platform |
| Service account create / disable / enable | :373 / :510 / :542 | `service_account:*` | yes | — | Platform |
| Service-account key create / revoke | :240 / :598 | `api_key:create` / `api_key:revoke` | yes | **yes** | Platform |
| **Authenticate a request with a key** | `validate_api_key` | authentication only | **yes, opt-in per route (ADR-0047)** | `X-API-Key` | Platform — `require_permission(..., api_key=True)`; never on an authority resource |

The `core.api_keys` table is global, not RLS-scoped; the functions filter by explicit `tenant_id`. `docs/API-ARCHITECTURE.md:41` already specifies rate limiting "scoped by tenant and by API key", which G3 has to satisfy.

### 3.5 Billing — `saas_os/core/billing/`

| Capability | Function | Core authorization | Fits chain | Secret | Proposed owner |
|---|---|---|---|---|---|
| Catalog read | `catalog.list_plans` :242 | `billing.catalog:read` | yes | — | Platform |
| Catalog manage | `create_owned_plan`, `set_plan_visibility`, `withdraw_plan`, offers | `billing.catalog:manage` | yes | — | Product |
| Merchant / billing accounts | `parties.py` | `billing.merchant:manage`, `billing.account:manage` | yes | — | Product |
| Subscribe | `commercial.create_subscription` :589 | dual: `billing.account:charge` at the payer **and** `billing.subscription:create` at the service tenant; idempotency key mandatory | partly — two tenants are authorized, the chain resolves one | — | Product |
| Cancel / reconcile | :1178 / :1038 | `billing.subscription:cancel\|read` | yes | — | Product |
| Payment page | `commercial.get_payment_page` | `billing.subscription:read` at the service tenant and `billing.account:charge` at the payer; `pending` or `past_due` only; re-authorized after the provider call | **yes (ADR-0052)** | — | Platform — `POST .../billing/subscriptions/{id}/payment-page` in `build_billing_router()` |
| Subscription read models | `projections.py` (not exported) | authorized | yes | — | Product |
| Entitlements read | `get_entitlements` :784 | ungated | yes | — | Platform |
| Legacy path | `service.subscribe`, `upgrade_subscription`, `cancel_subscription` | **none** — "a consumer exposing them to an end user must authorize first" (`service.py:63-67`) | must not be routed | — | none; retirement already deferred |
| Inbound provider webhook | `process_provider_event` (via `parse_stripe_event`) | signature over the raw body | **yes, opt-in (ADR-0048)** | `POST /v1/billing/providers/stripe/events` | Platform — `build_stripe_billing_events_router()`, public, signature-only |

Checkout, pricing pages, plan selection and payer/merchant relationships differ by product (B2B, B2C, B2B2C). ADR-0029 and the roadmap already assign usage-report routes to products ("products own routes, ADR-0017"). `ServiceAccountCaller` is not accepted by billing authorization yet (`authorization.py:43-45`).

### 3.6 Outbound webhooks — `saas_os/core/webhooks/service.py`

| Capability | Function | Core authorization | Fits chain | Secret | Proposed owner |
|---|---|---|---|---|---|
| Subscribe an endpoint | `subscribe` :585 | `webhook_subscription:create` | yes | **yes — signing secret once** | Platform |
| Unsubscribe | `unsubscribe` :671 | `webhook_subscription:delete` | yes | — | Platform |
| List / get | :657 / :648 | ungated read | yes — needs a read permission | — | Platform |
| Update, enable/disable, rotate secret | not implemented (ADR-0035) | — | — | — | not available |
| Delivery history, replay | no delivery entity exists; replay deferred (ADR-0035) | — | — | — | not available |
| Emit an event | `trigger_event` :926 | trusts caller | never routed | — | Product code calls it |

At subscribe, only a destination given as a literal IP address is checked; a host name is resolved, and every address it resolves to checked, before each delivery (`_validate_url()`, `_validate_destination()`). `http://` targets are still accepted (ADR-0035), which a public route makes more exposed.

### 3.7 Feature flags — `saas_os/core/feature_flags/service.py`

| Capability | Function | Core authorization | Fits chain | Secret | Proposed owner |
|---|---|---|---|---|---|
| Create / list flags (global catalog) | `create_flag` :64, `list_flags` :89 | **none, unaudited** | no (G1) | — | Operator |
| Set / remove tenant override | :100 / :167 | **none**; audited | no permission exists | — | Operator |
| Evaluate | `evaluate_flag` :219 | trusts caller | yes | — | Product |

No permission is registered for flags and the module "trusts its caller's `tenant_id` argument". A tenant override changes what a tenant can do — the self-learning kill switch is a flag — so letting a tenant administrator set one is a privilege decision, not a convenience route.

### 3.8 Usage — `saas_os/core/usage/`

| Capability | Function | Core authorization | Fits chain | Secret | Proposed owner |
|---|---|---|---|---|---|
| Record usage | `ingest_event` :141 | none, by design (ADR-0037) | no — a client would assert its own consumption; needs G3 and idempotency | — | Product (server-side call) |
| Quota check / consume | `check_quota`, `consume_quota_idempotent` | none | already wired as `require_entitlement_and_quota` | — | exists as a dependency |
| Reports | `reporting.service_tenant_usage_report` :193 and two others | `billing.subscription:read`, `billing.account:read`, `billing.merchant:manage` | yes | — | Product (ADR-0029 already says so) |

## 4. Summary by proposed owner

| Owner | Capabilities |
|---|---|
| **Platform, fits today** (authorized in Core, tenant-scoped, session caller) | members; invitations except accept; own and service-account API keys; service accounts; webhook subscriptions; catalog read; entitlements read |
| **Platform, blocked by a gap** | None. Invitation accept (G2) is implemented by ADR-0046, API-key request authentication (G3) by ADR-0047, the inbound billing webhook (G4) by ADR-0048 |
| **Product** | sign-up and tenant creation flow; checkout and subscription management; merchant/payer setup; usage ingestion and reports; flag evaluation; everything domain-specific |
| **Operator, no route** | tenant lifecycle and purge; identity erasure; flag catalog and overrides; first-tenant bootstrap |

## 5. Existing binding statements an ADR must respect

1. ADR-0017 Decision: SaaS OS "may expose reusable API infrastructure/components (… ingress chain, standard error-response shaping, health/readiness endpoints), but a consumer must never be forced to import a complete SaaS OS application or server". Capability routers are not in that list, and are compatible with it only if opt-in.
2. `docs/API-ARCHITECTURE.md:17` assigns "Core capability routes (billing, api-keys, webhooks, feature-flags, audit-log query)" to "each respective `saas_os/core/*` module", while every Core `__init__` says the module does not own an HTTP surface. The two statements conflict and nothing resolves them.
3. `saas_os/api/__init__.py:47-49`: Core-capability routes "each get their own route family in a future phase with an actual tested need".
4. ADR-0029 and the roadmap: usage-report routes are product-owned.
5. `docs/ARCHITECTURE.md:148`: "Each Product owns its own external-facing API routes for product-specific functionality".
6. ADR-0030: every route declares exactly one policy; a public route needs a stated reason.
7. ADR-0006: REST and OpenAPI, `/v1/` from the first route.
8. Import-linter: `api` may not import `saas_os.core.identity.erasure`, `saas_os.infra.db.backup`, `products` or `control_plane`.
