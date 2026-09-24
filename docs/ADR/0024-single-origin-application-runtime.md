# ADR-0024: Single-origin application runtime and the reusable local edge

Status: Accepted
Date: 2026-09-24
Supersedes / Superseded by: —

## Context

A browser-facing SaaS application built on SaaS-OS is two servers: the
product's frontend and the product's backend (which is where SaaS-OS's own
`/auth/*` OIDC flow and `/v1/*` API live). To the browser they must look
like **one origin**, because the three things that actually carry a login
are all origin-scoped:

- the session cookie (`AUTH_COOKIE_NAME`, `HttpOnly`, `SameSite=Lax`, `Path=/`)
- the OIDC redirect URI the provider will send the authorization code to
- every relative `fetch("/v1/...")` the frontend makes

Production already works this way. `docker-compose.prod.yml` + the
repository-root `Caddyfile` (P2.3, extended by ADR-0023 Phase 3) put one
Caddy site in front of `backend` and `frontend`, routing `/auth/*` and
`/v1/*` to the backend and everything else to the frontend, with `backend`
and `frontend` publishing no host port at all.

Local development did not. `docker compose up` published `backend` on
:8000 and `frontend` on :3000 — two distinct origins — with
`OIDC_REDIRECT_URI=http://localhost:8000/auth/callback`, a callback on the
*backend's* origin rather than the application's. That gap is not merely
cosmetic for a downstream product (ADR-0015): every consuming project that
wants a working browser login has to independently invent the same five
things — a local reverse proxy, its routing rules, a callback origin, a
browser-visible API origin for its frontend, and the matching ZITADEL
redirect-URI registration — and each will get them subtly differently.
`docs/LOCAL-IDENTITY.md` already documents the ZITADEL half of the local
topology as a one-time scaffold copy; the origin/edge half had no answer at
all.

The constraint that shapes the answer is ADR-0015: SaaS-OS is consumed as
an installed package, and a consumer must not have to copy this
repository's files to get reusable behavior. The constraint that bounds it
is that SaaS-OS must not learn anything about a product's own routes —
`/dashboard`, `/app`, `/t/{tenant_id}/...` are the product's, permanently.

## Options Considered

### Option A — Document the pattern, ship nothing
- Advantages: zero new code, no new distribution surface
- Disadvantages: does not meet the goal — every consuming project still
  authors its own proxy configuration and its own callback-origin
  reasoning, which is exactly the duplication this phase exists to remove;
  a routing mistake (exposing an internal service, or missing `/v1/*`) is
  silent and per-project

### Option B — Ship the edge configuration as package data plus one console script that emits it, and derive the OIDC callback from a declared public origin
- Advantages: reuses the two conventions this repository already has for
  exactly this shape of problem — package data shipped inside the wheel
  (`infra.db`'s Alembic environment, ADR-0016) and a console script a
  consumer runs from its installed dependency (`saas-os-local-identity`,
  ADR-0023 Phase 1); the routing contract becomes a tested Python constant
  rather than prose; the callback stops being a second value that can drift
  from the origin; a consumer sets one variable
- Disadvantages: adds a (small) non-Python asset to the distributed
  package; the emitted file is Caddy-specific, so a consumer wanting a
  different proxy writes their own

### Option C — A configurable edge service/framework (routes declared in YAML or an env-driven DSL, rendered into proxy configuration)
- Advantages: proxy-agnostic; a product could add arbitrary routes without
  editing a file
- Disadvantages: builds a general-purpose reverse-proxy configuration
  system nothing has asked for; every route made configurable is a route
  that can be misconfigured into exposing PostgreSQL, Redis, the worker, or
  ZITADEL's database; directly contradicts this repository's established
  "defer infrastructure until evidence demands it" discipline (ADR-0007,
  ADR-0010, ADR-0012)

### Option D — Make the local topology single-origin by serving the frontend from the backend process (static files mounted on FastAPI)
- Advantages: one process, no proxy at all
- Disadvantages: breaks Next.js development entirely (no dev server, no
  hot reload); makes SaaS-OS's backend responsible for serving the
  product's frontend, which is precisely the ownership inversion this ADR
  exists to prevent

## Recommendation

Option B. Options A and D are rejected outright; Option C is rejected for
now and would need its own ADR and real evidence to revisit.

## Decision

**Accepted.** The following are binding:

1. `PUBLIC_APP_ORIGIN` is the browser-visible origin the whole application
   is served on. It is an *origin*: scheme + host + optional port, with no
   path, query, fragment, or credentials, and `https` whenever
   `ENVIRONMENT=production`. It is never an internal container address —
   internal services keep addressing each other over Compose DNS
   (`http://backend:8000`, `http://frontend:3000`).
2. The OIDC redirect URI is **derived** from it:
   `PUBLIC_APP_ORIGIN + "/auth/callback"`. The callback path is fixed, not
   configurable — it is `api/auth/routes.py`'s own route, and a
   configurable one would let a deployment register a callback the
   application does not serve.
3. `OIDC_REDIRECT_URI` remains supported and behaves exactly as before when
   it is the only one set (backward compatibility for the existing
   two-origin local workflow, and for any deployment whose callback is
   genuinely not on the application origin). Setting both to values that
   disagree is a fail-closed configuration error — never silent precedence
   either way.
4. The public path surface the **backend** owns behind that origin is a
   closed, declared list (`infra/edge/routing.py`): `/auth/*`, `/v1/*`,
   and — locally only — `/healthz`, `/readyz`. Everything else reaches the
   product frontend, by exclusion rather than by enumeration.
5. SaaS-OS ships one reusable **local-development** edge configuration as
   package data (`infra/edge/assets/Caddyfile.local-edge`), emitted by the
   `saas-os-edge-config` console script. This repository's own
   `docker-compose.yml` mounts that exact file — SaaS-OS is the first
   consumer of its own reusable edge, never a parallel hand-written copy.
6. The edge proxies exactly two upstreams: the product backend and the
   product frontend. No internal service (PostgreSQL, Redis, the worker,
   ZITADEL, ZITADEL's database) has a route through it, and none may be
   added. Caddy's admin API is disabled in the shipped configuration.
7. SaaS-OS does not own the product's authenticated destination. After a
   successful login the browser is sent to `AUTH_POST_LOGIN_PATH` — a
   fixed, same-origin absolute path, `/` by default. What that path renders
   is entirely the product frontend's decision. No SaaS-OS module contains,
   or may contain, a product route such as `/dashboard`, `/app`, or
   `/t/{tenant_id}/...`.
8. No browser-supplied post-login destination is introduced. There is no
   `?next=`, no request-supplied `redirect_uri`, and no mechanism by which
   a request can influence where the browser goes after login. The
   pre-existing same-origin validation on `AUTH_POST_LOGIN_PATH` is
   unchanged.
9. The emitted edge configuration is the consuming project's own file from
   the moment it is written (ADR-0015 rules 9/10). SaaS-OS does not track,
   version, or upgrade a project's copy.

### The boundary

```
SaaS-OS                                  Product
-------                                  -------
identity / OIDC relying party            frontend
local identity bootstrap                 backend business routes
PUBLIC_APP_ORIGIN contract               authenticated entry route
callback derivation                      dashboard
backend/frontend origin routing          navigation
local edge composition                   tenant UX
```

```
Product
  -> depends on saas-os (pinned package, ADR-0015)
  -> sets PUBLIC_APP_ORIGIN
  -> runs saas-os-edge-config, adds an edge service to its Compose file
  -> keeps using SaaS-OS identity (saas-os-local-identity, ADR-0023)
  = single-origin browser application
```

## Security properties

Unchanged by this ADR, and now additionally asserted by its own tests:

- OIDC Authorization Code flow with PKCE (S256) — `core/identity` enforces
  it regardless of any edge configuration.
- The callback is a single allowlisted URI the browser never chooses; it is
  registered with the provider and sent again in the token exchange.
- A fixed, same-origin post-login destination; no arbitrary redirects.
- No access token in `localStorage`, in a URL, or in frontend code — the
  session remains an `HttpOnly` cookie.
- No credential reaches the edge: the `edge` service declares no
  `env_file` and no environment at all.
- No secret is added to any tracked file — `PUBLIC_APP_ORIGIN` and
  `SAAS_OS_EDGE_PORT` are non-secret, and the emitted Caddy configuration
  contains none.

Strengthened:

- A deployment can no longer silently hold a callback on a different origin
  than the application it serves (rule 3's fail-closed check).
- The set of browser-reachable backend paths is a tested constant, checked
  against the application's real route table, so a new public path cannot
  appear at the edge by accident and an internal service cannot be routed
  through it.

## Local vs production

These are deliberately **not** the same artifact:

| | Local (this ADR) | Production (P2.3 / ADR-0023 Phase 3) |
|---|---|---|
| Configuration | `infra/edge/assets/Caddyfile.local-edge` (packaged, emitted by `saas-os-edge-config`) | repository-root `Caddyfile` |
| Composition | `docker-compose.yml`'s `edge` service | `docker-compose.prod.yml`'s `proxy` service |
| TLS | none — plaintext `:8080`, `auto_https off` | ACME/automatic HTTPS, TLS 1.2+, HSTS |
| `/healthz`, `/readyz` | proxied to the backend (developer convenience) | **not** proxied to the backend, deliberately |
| Identity | ZITADEL on its own host port | ZITADEL on an operator-controlled subdomain, private network |
| Ports published | `edge`, plus `backend`/`frontend` as a developer escape hatch | the proxy only |

The local edge does not solve production deployment and does not claim to.
This repository's production edge already existed and is *integrated with*
here — it now derives `PUBLIC_APP_ORIGIN` from the `PUBLIC_DOMAIN` it
already terminates TLS for — not duplicated. A downstream product designs
its own production edge; SaaS-OS does not invent a deployment provider for
it, and production edge composition for consuming projects remains
unstandardized.

## What Would Be Difficult to Change Later

The derivation in rule 2 and the closed route list in rule 4 are cheap to
extend and expensive to *narrow* once products depend on them: removing a
prefix from the contract silently sends live browser traffic to the
frontend instead of the backend. Rule 7 is the genuine one-way door — the
moment any SaaS-OS module encodes a product's authenticated route, every
consumer that came to rely on it has to be untangled from that assumption,
the same reasoning ADR-0015 rule 5 records for the repository boundary.

## What Is Deliberately Not Decided Here

- Any proxy other than Caddy. The emitted configuration is Caddy-specific;
  a consumer using something else writes their own against the same
  declared contract.
- Production edge composition for downstream products — unstandardized, and
  left that way (this repository's own production topology is a reference
  deployment, not a shipped product deployment).
- A frontend API-origin variable. None is introduced: with one origin the
  correct call is a relative URL (`fetch("/v1/...")`), and no local port is
  baked into reusable SaaS-OS frontend infrastructure. Should a future
  frontend genuinely need an explicit base URL, it derives from
  `PUBLIC_APP_ORIGIN`.
- A Content-Security-Policy for the local edge — the same deferral the
  production Caddyfile already records (no inline-script/style inventory
  exists to build a real policy against yet).
- Any change to authentication, session management, tenant authorization,
  or the API itself. This ADR adds no route, no schema change, and no
  second session mechanism.

## Related

ADR-0015 (distribution/consumer boundary — why the edge ships as package
data plus a console script rather than as files a consumer copies);
ADR-0017 (`build_platform_app()` — the backend surface this edge routes
to); ADR-0023 (self-hosted provider-neutral identity — the OIDC flow whose
callback this origin now derives, unchanged); ADR-0006 (`/v1/*` API
versioning); ADR-0010 (Docker Compose deployment target);
`docs/LOCAL-IDENTITY.md`; `docs/DEPLOYMENT-ARCHITECTURE.md`.
