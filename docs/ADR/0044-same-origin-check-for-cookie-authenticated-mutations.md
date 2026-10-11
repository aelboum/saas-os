# ADR-0044: Same-origin check for cookie-authenticated mutations

Status: Accepted (2026-10-11) and implemented
Date: 2026-10-11
Supersedes / Superseded by: —

## Context

A browser attaches the session cookie to every request it sends to the application's host, including a request that a different page caused. The platform's defense was the cookie's `SameSite=Lax` attribute alone; `saas_os/api/auth/routes.py` said so explicitly ("No CSRF framework exists in this repository to reuse; none is invented").

`SameSite` is about *sites*, not origins. A site is the registrable domain, so `app.example.com` and `anything-else.example.com` are the same site. `Lax` withholds the cookie on a cross-site `POST`; it sends it on a same-site one. An attacker who controls any sibling subdomain — a forgotten marketing host, a user-content domain, a subdomain takeover — could therefore make a signed-in user's browser send a state-changing request with the cookie attached.

Until ADR-0040 the only state-changing route was `POST /auth/logout`. The opt-in capability routers added ten more (membership suspend/reactivate/revoke, invitation create/revoke, API-key create/rotate/revoke, subscribe, cancel), several of them bodyless `POST`s that a plain HTML form can issue. The independent review of ADR-0040 recorded this as an open MEDIUM finding. The repository owner asked for a server-side defense that includes `Origin` validation, preserves Bearer-token clients, and does not silently break legitimate non-browser clients.

## Options Considered

### Option A — `SameSite=Strict`
- Advantages: one attribute.
- Disadvantages: still site-scoped, so it does not address the sibling-subdomain case at all; breaks the post-login top-level navigation back from the identity provider.

### Option B — Synchronizer or double-submit token
A per-session secret the frontend must echo in a header or field.
- Advantages: the classic defense; works without `Origin`.
- Disadvantages: needs an endpoint to obtain the token, client code in every product frontend, and (double-submit) is itself weakened by a sibling subdomain that can set cookies for the parent domain — the very attacker in question. SaaS OS ships no frontend (ADR-0042) to carry the client half.

### Option C — Verify the request's origin on the server
For an unsafe method authenticated by cookie, require the browser's own `Origin` header to equal the application's origin, and treat `Sec-Fetch-Site`, when present, as a second witness.
- Advantages: entirely server-side, nothing for a product frontend to implement; `Origin` is set by the browser and cannot be forged by page script; it distinguishes origins, not sites, so a sibling subdomain fails; the trusted origin already exists as configuration (`PUBLIC_APP_ORIGIN`, ADR-0024).
- Disadvantages: a non-browser client that authenticates with the cookie and sends no `Origin` is refused.

### Option D — Require a custom request header (e.g. `X-Requested-With`)
- Advantages: also server-side; a cross-origin page cannot add a custom header without a CORS preflight.
- Disadvantages: every legitimate browser client must be changed to send it, which Option C does not require.

## Recommendation

Option C. It needs no client change for a real browser, fails closed, and uses a value the deployment already declares.

## Decision

**Accepted by the repository owner on 2026-10-11; Option C, implemented** in `saas_os/api/dependencies.py`.

1. **When it applies.** The request authenticates with the session cookie (a cookie is present and no `Authorization` header replaces it) **and** its method is not `GET`, `HEAD` or `OPTIONS`.
2. **What is required.**
   - an `Origin` header that is exactly an origin (scheme, host, optional port — no path, query, credentials, and not `null`) and equals the trusted origin after normalization (case-insensitive scheme and host, default port dropped);
   - if the browser sent `Sec-Fetch-Site`, its value is `same-origin`.
3. **The trusted origin** is `PUBLIC_APP_ORIGIN`. For a deployment that declares only `OIDC_REDIRECT_URI`, it is that callback's origin, which is the host that set the cookie. If neither yields an origin, cookie-authenticated mutations are refused.
4. **Refusal** is the generic `403 {"detail": "Not authorized."}`. The reason (`origin_missing`, `origin_mismatch`, `fetch_site_not_same_origin`, `no_trusted_origin_configured`) goes to a structured log event `csrf_rejected` on logger `saas_os.api.csrf`, with the method and no request value.
5. **Bearer clients are exempt.** A request carrying `Authorization: Bearer …` is never checked: a page cannot make a browser attach that header to another origin without a CORS preflight, and this API answers none. Scripts, services and a frontend that holds the token itself are unaffected, with or without an `Origin` header.
6. **Safe methods are exempt**, and must stay free of state changes.
7. **A request with no credential** still gets authentication's own `401`.
8. **Where it runs.** As a sub-dependency of `get_current_session` and `get_current_actor`, the two functions every authenticated route policy resolves through — ahead of session validation, tenant resolution, rate limiting and authorization. A route cannot be authenticated without passing it, and no router has to opt in.

## Compatibility

- **Browsers**: no change. Every current browser sends `Origin` on every non-`GET`/`HEAD` request, same-origin included.
- **`POST /auth/logout`** is cookie-authenticated and now requires a matching `Origin`. A script that logged out by replaying only the cookie gets `403`; it should send `Origin`, or authenticate with `Authorization: Bearer`.
- **Any non-browser client that authenticates with the cookie** on a mutating request is affected the same way. This is deliberate, not silent: the cookie is the browser transport, and the header transport exists for everything else.
- **A reverse proxy that strips or rewrites `Origin`** breaks cookie-authenticated mutations. The repository's own Caddy configuration does neither.
- **`PUBLIC_APP_ORIGIN` must be the origin the browser actually uses**, as ADR-0024 already requires.

## Evidence

`tests/api/test_csrf_unit.py` (85 tests): same-origin accepted, including case and default-port variants and matching fetch metadata; refused for an unrelated site, a sibling subdomain, the parent domain, a look-alike suffix, another port and a downgraded scheme; refused with no `Origin`; refused for nine malformed `Origin` values; refused when `Sec-Fetch-Site` is `same-site`, `cross-site` or `none` despite a matching `Origin`; the state change (`revoke_session`) observed not to happen on every refusal; the log event carrying a reason and no request value; Bearer clients unaffected with no `Origin`, a hostile one, or a cookie alongside; safe methods unchecked; no credential still `401`; a dead session from the right origin still `401`; both authenticated dependencies; `PUBLIC_APP_ORIGIN` as the trusted origin; and each of the ten state-changing capability routes refusing four forged variants before any database access. Negative control: with the check replaced by a no-op, the sibling-subdomain request succeeds.

`tests/api/v1/test_capability_routers_integration.py` (real PostgreSQL): four forged cookie requests against membership suspend change nothing and write no audit row; the same request from the application's origin succeeds; a Bearer client mutates with no `Origin` and with a hostile one.

## Limits

- **Not a token.** A deployment whose `PUBLIC_APP_ORIGIN` also serves attacker-controlled script (stored XSS on the application's own origin) is not protected by any CSRF defense, this one included.
- **`GET` routes with side effects** would not be covered; the platform has none on authenticated paths, and `GET /auth/callback` is protected by its single-use, cookie-bound `state`.
- **Sibling subdomains can still set cookies for the parent domain** (cookie tossing). That does not let them pass this check, but a product should still not host untrusted content under its application's registrable domain.

## What Would Be Difficult to Change Later

Relaxing it. Once products rely on forged same-site requests being refused, accepting a missing `Origin` again would silently reopen the hole for them. Adding a token on top later is additive and easy.

## Related

ADR-0005 and `saas_os/api/auth/routes.py` (session cookie; the earlier "SameSite only" stance this ADR replaces); ADR-0024 (`PUBLIC_APP_ORIGIN`); ADR-0030 (route policy: the dependencies this check is attached to); ADR-0040 (the routes that widened the exposure); ADR-0042 (no platform frontend to carry a token); `docs/SECURITY.md`.
