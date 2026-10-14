# ADR-0047: API-key request authentication

Status: Accepted (2026-10-14) and implemented — the repository owner approved the recommendations on transport, opt-in routes, the principal, the per-key rate limit, key lifetime and the same-origin exemption.
Date: 2026-10-14
Supersedes / Superseded by: — (closes gap G3 of [ADR-0040](0040-reusable-http-platform-capabilities.md))
Related: ADR-0030 (route policies), ADR-0031 (callers), ADR-0044 (same-origin check), ADR-0045 (platform authority, and its constraint on G3).

## Context

`saas_os.core.api_keys.validate_api_key(raw_key)` authenticates a key: it refuses a revoked or expired key, a key whose tenant does not admit its principals, a user-owned key whose user is inactive, and a service-account key whose service account is disabled, and it audits each refusal. Nothing at ingress calls it: `get_current_actor()` accepts a session only, `RequestContext` carries a user and a membership, and a product that wants machine access writes its own authentication.

ADR-0040 listed six questions. ADR-0045 added one constraint: any request-authentication path must authenticate through `validate_api_key` (or otherwise honour `revoked_at`), because user deactivation revokes keys.

Facts established while preparing this ADR:

- Keys and session tokens have the same shape (`secrets.token_urlsafe(32)`), so sharing `Authorization: Bearer` would need a database lookup to tell them apart.
- A key belongs to exactly one tenant (`core.api_keys.tenant_id`).
- A suspended member's key authenticates, but `can()` refuses any membership that is not `ACTIVE`, so it fails at authorization. ADR-0040's item 5 is therefore narrower than it reads: the gap is expiry, not suspension.
- Rate limiting is keyed by tenant and path only; `docs/API-ARCHITECTURE.md` specifies a per-key limit too.
- Billing's authorization does not accept `ServiceAccountCaller`.

## Decision

1. **Transport.** A key is presented in its own header, `X-API-Key`. It is never accepted in `Authorization` or in a cookie, and a request that carries a key and also a session credential (an `Authorization` header or the session cookie) is refused with the generic `401`: one request, one principal. New keys carry a fixed, visible prefix, `sok_`, so that a key is recognisable to people and to secret scanners; the prefix is part of the secret that is hashed, and keys issued before this ADR, without it, keep working.
2. **Which routes.** Only a route that opts in accepts a key: `require_permission(resource, action, api_key=True)` (and `require_entitlement_and_quota(..., api_key=True)`, which wraps it). The route policy records the opt-in (`RoutePolicy.accepts_api_key`). A permission that changes authority never accepts a key: asking for it is a `ValueError` when the route is defined, so such an application cannot even be assembled. The test is `saas_os.core.rbac.is_authority_changing(resource, action)`: every capability on a resource in `AUTHORITY_RESOURCES` (memberships and their roles, roles and role permissions, invitations, API keys, service accounts and their roles, delegations, denies, support access, webhook subscriptions), the billing mutations (creating, changing, cancelling or reactivating a subscription; charging or managing an account; managing a catalog or a merchant) and tenant self-suspension. That is exactly the set a support-access grant may never satisfy. The check is by permission: a product that gates an authority-changing handler of its own on some other permission name is outside what Core can see. No Core router opts in by this ADR; a product opts in its own routes.
3. **The principal.** A user-owned key acts as its user: the request's actor is that user, with the user's membership in the key's tenant, exactly as a session would give, and Core callers built from it are `UserCaller`. A service-account key acts as its service account: `RequestContext.principal` is `RequestPrincipal.SERVICE_ACCOUNT`, `actor_id` is the service account's id, `membership_id` is `None`, and the caller built from it is `ServiceAccountCaller`. `can()` is evaluated with `actor_type=SERVICE_ACCOUNT` and the key's tenant as the service account's own. `saas_os.api.v1._common.user_caller()` refuses a service account (`403`) rather than turn its id into a user; `request_caller()` returns either. Billing keeps refusing service accounts; a route that needs billing authority must not opt in for them until a later decision says otherwise.
4. **Tenant.** The tenant in the path must be the key's own tenant. Any other tenant is the same `404` a non-member gets: a key never reaches another tenant, a parent's included, and never learns whether the tenant exists.
5. **Rate limit.** A key-authenticated request is limited per key (`api-key:<key id>`) in addition to the existing per-tenant limit, failing closed like the existing limiter (`503` when the backend fails).
6. **Lifetime.** A key issued or rotated over HTTP expires: the request may give `expires_in_days` from 1 to 365, default 365, and rotating over HTTP gives the new key the same bound even when the old key had none. Keys created directly through Core keep the optional `expires_at` of their function (a product's own tooling decides). A suspended member's key is refused at authorization (`can()`), as today; nothing changes there.
7. **Cross-origin requests.** ADR-0044 exempts header credentials from the same-origin check because a browser cannot be made to attach them cross-origin; `X-API-Key` is such a header (a cross-origin page needs a CORS preflight the application does not grant). A request with both a key and a cookie is refused (item 1), so a cookie cannot ride along with a key.
8. **Audit.** Every refusal `validate_api_key` makes is audited as today. An authorization or entitlement refusal of a key-authenticated request is the existing `api.access_denied` row, with the service account as actor when the key is one's. A successful authentication is not audited, as a session's is not, and neither is a valid key presented to another tenant, as a session's non-member request is not.

## Consequences

- A product exposes machine access by adding `api_key=True` to the routes it chooses, with no authentication code of its own.
- `RequestContext` gains two fields with defaults (`principal`, `api_key_id`) and `membership_id` becomes optional. Existing routes, which do not opt in, only ever see a user principal with a membership; a route that opts in must handle a service account.
- A key presented to a route that does not opt in is ignored: that route still needs a session, and answers `401` without one.
- No key can manage authority, by construction at startup.
- The key format changes for new keys only.
- On a route that opts in, `RequestContext.actor_id` may be a service account's id. A product must not use it as a user id there (`UserCaller(context.actor_id)`, a column that references `core.users`): `user_caller()` refuses a service account, `request_caller()` gives the right caller, and `context.principal` says which.
- The rate limit runs after authentication, as it does for sessions. A revoked or expired key can therefore be replayed without limit, and each attempt writes the `api_key.validate` refusal row `validate_api_key` already writes. Recorded as a LOW item in the roadmap ledger; a limit before authentication (keyed, for instance, by a hash of the presented credential, for sessions and keys alike) is a separate decision.

## Implementation

- `saas_os/api/dependencies.py`: `require_permission(..., api_key=True)` and the chain behind it (`_tenant_context_accepting_api_key`, `_api_key_context`, the per-key limit in `_enforce_rate_limit`); denial audit rows name the service account when the key is one's.
- `saas_os/api/context.py`: `RequestPrincipal`, `RequestContext.principal`, `RequestContext.api_key_id`; `saas_os/api/route_policy.py`: `RoutePolicy.accepts_api_key`.
- `saas_os/core/api_keys/service.py`: the `API_KEY_PREFIX` constant, `sok_`, on every new key; `rotate_api_key(..., expires_no_later_than=...)`. `saas_os/api/v1/api_keys.py`: `expires_in_days` (1 to 365, default 365) and the bounded rotation.
- Tests: `tests/api/v1/test_api_key_request_auth_integration.py` (opt-in, both principals, one tenant including a child tenant, every non-authenticating key the same `401`, a key with a session credential, a pre-prefix key, authorization and its audit, the per-key limit and its `429`, lifetime over HTTP) and `tests/api/test_request_caller_unit.py`. Negative controls, run by mutating the code and restoring it: without the tenant match a service-account key reaches another tenant; without the "one principal" rule a key with a session is accepted; without the per-key limit the limiter is never asked about the key; with a service account evaluated as a user it is refused its own permission.

## Not decided here

- A rate limit before authentication, for keys and sessions alike (see Consequences).

- Opting Core's own routers in (usage ingestion is the obvious candidate) — a later change, route by route.
- Service accounts in billing.
- Scoped keys (a key restricted to fewer permissions than its owner).
