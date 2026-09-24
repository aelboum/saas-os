# Single-origin application runtime

How a SaaS-OS-based product serves its backend, its frontend and its login
flow on **one browser origin**, and which half of that each side owns.
The decision and its trade-offs are
`docs/ADR/0024-single-origin-application-runtime.md`; this document is the
operational guide.

## The shape

```
                         Browser
                            |
                   PUBLIC_APP_ORIGIN            (one origin)
                            |
                         edge (Caddy)
                     /                \
   /auth/*  /v1/*  /healthz  /readyz    everything else
            |                                   |
     Product backend                     Product frontend
   (saas-os: identity, API)         (product: routes, dashboard, UX)
```

One origin is not cosmetic. The session cookie, the OIDC redirect URI, and
every relative `fetch("/v1/...")` are all origin-scoped, so a two-origin
topology forces cross-origin cookie handling, CORS configuration, and a
callback registered against the wrong host.

`PUBLIC_APP_ORIGIN` is what the **browser** sees. Internal services keep
addressing each other over Compose DNS — `http://backend:8000`,
`http://frontend:3000`. The two are never the same value.

## Who owns what

| SaaS-OS provides | The product provides |
|---|---|
| identity/authentication primitives (`core/identity`, `api/auth`) | its frontend |
| local identity bootstrap (`saas-os-local-identity`, ADR-0023) | its backend and business routes |
| the `PUBLIC_APP_ORIGIN` contract and the OIDC callback derived from it | its authenticated entry route |
| backend/frontend browser-origin routing (`infra/edge/routing.py`) | its dashboard |
| reusable local edge composition (`saas-os-edge-config`) | its navigation and tenant UX |

SaaS-OS does not know — and must never encode — what a product's
authenticated destination is. There is no `/dashboard`, `/app`, or
`/t/{tenant_id}/...` anywhere in SaaS-OS. After a successful login the
browser is sent to `AUTH_POST_LOGIN_PATH`, a fixed same-origin absolute
path (`/` by default); what that path renders is the product frontend's
decision alone.

## Configuration

Everything a downstream product must set:

```bash
# The one browser-visible origin. Scheme + host + optional port only --
# no path, query, fragment or credentials; https when ENVIRONMENT=production.
PUBLIC_APP_ORIGIN=http://localhost:8080

# Host port the local edge publishes. Must match the port above.
SAAS_OS_EDGE_PORT=8080
```

That is the whole reusable-runtime surface. In particular:

- **`OIDC_REDIRECT_URI` is normally not set.** It is derived as
  `PUBLIC_APP_ORIGIN + /auth/callback` — by the backend
  (`api/auth/config.py`) and by the identity bootstrap that registers it
  with the provider (`saas-os-local-identity`), from the same helper, so
  the two cannot drift. Set it explicitly only for a callback that is
  genuinely not on the application origin; setting both to values that
  **disagree fails closed** at startup rather than silently picking one.
- **No frontend API-origin variable exists.** With one origin the correct
  call is a relative URL:

  ```ts
  await fetch("/auth/me");          // not http://localhost:8000/auth/me
  await fetch("/v1/tenants/…");
  ```

  No local development port belongs in reusable frontend code.
- **`AUTH_POST_LOGIN_PATH`** stays a fixed, same-origin absolute path. There
  is no `?next=` parameter and no other browser-supplied destination,
  anywhere.

Optional, and **not** product `.env` settings: two Caddy `{$VAR}`
substitutions, read from the **edge container's own environment** when a
product's services are not named `backend`/`frontend`:

```bash
SAAS_OS_BACKEND_INTERNAL_ORIGIN=http://my-api:8000    # default: http://backend:8000
SAAS_OS_FRONTEND_INTERNAL_ORIGIN=http://my-web:3000   # default: http://frontend:3000
```

No Python code reads either one; they are resolved by Caddy itself, inside
the edge container, when it loads the configuration. Putting them in the
product `.env` therefore has no effect on its own — the standard SaaS-OS
`edge` service deliberately receives neither an `env_file` nor an
`environment` block, so nothing forwards them. A product that needs them
supplies them on its own edge service (the one it owns, alongside the edge
configuration it owns — see below). Services named `backend`/`frontend`, the
default, need no override at all.

## Routing contract

| Path | Goes to |
|---|---|
| `/auth/*` | backend — the OIDC flow (`api/auth/routes.py`) |
| `/v1/*` | backend — the versioned external API (ADR-0006), including the product's own routers |
| `/healthz`, `/readyz` | backend — **local only**; the production Caddyfile deliberately does not proxy these |
| everything else | the product frontend |

This is a closed list (`infra/edge/routing.py`), checked by
`tests/api/test_single_origin_routing_unit.py` against the route table the
application actually mounts. It is not a programmable proxy: no internal
service — PostgreSQL, Redis, the worker, ZITADEL or ZITADEL's database —
has a route through the edge, and none may be added. FastAPI's `/docs`,
`/redoc` and `/openapi.json` are deliberately not proxied either; reach
them on the backend's own direct port while developing.

A product that needs an additional browser-facing backend prefix edits the
edge configuration it owns (below).

## Local development

### In this repository

```bash
cp .env.example .env     # first time only
docker compose up -d
curl http://localhost:8080/readyz
```

`docker compose up` starts `db`, `redis`, `backend`, `worker`, `frontend`,
the local ZITADEL topology (`docs/LOCAL-IDENTITY.md`) and `edge`. The
browser uses `http://localhost:8080` for everything.

`backend` (:8000) and `frontend` (:3000) keep their published host ports as
a **developer-only escape hatch** — direct, un-proxied access to one
service (FastAPI's `/docs`, a Next.js error overlay, a raw `/v1` call).
The single-origin flow is the recommended one and needs neither port;
neither is ever published in `docker-compose.prod.yml`. An existing `.env`
that still sets `OIDC_REDIRECT_URI=http://localhost:8000/auth/callback` and
no `PUBLIC_APP_ORIGIN` keeps working exactly as it did before ADR-0024.

### In a downstream product

The product owns its own `docker-compose.yml`. From its installed `saas-os`
dependency it takes the edge configuration rather than writing one:

```bash
saas-os-edge-config --output local-dev/Caddyfile
```

and adds one service:

```yaml
  edge:
    image: caddy:2-alpine
    cap_drop: [ALL]
    ports:
      - "${SAAS_OS_EDGE_PORT:-8080}:8080"
    volumes:
      - ./local-dev/Caddyfile:/etc/caddy/Caddyfile:ro
    depends_on: [backend, frontend]
```

The emitted file is the product's own from that moment (ADR-0015 rules
9/10): SaaS-OS does not track, version or upgrade a project's copy. Re-run
with `--force` to take a newer SaaS-OS version's routing, then reapply any
local edits.

The identity half is unchanged and documented in `docs/LOCAL-IDENTITY.md` —
the same `zitadel`/`zitadel-db`/`zitadel-bootstrap` services, with
`PUBLIC_APP_ORIGIN` passed to the bootstrap so the callback it registers is
the one the backend will actually send.

End to end:

```
Product
  -> depends on saas-os (pinned package, ADR-0015)
  -> sets PUBLIC_APP_ORIGIN
  -> runs saas-os-edge-config, adds the edge service
  -> uses the existing SaaS-OS identity bootstrap
  = single-origin browser application
```

## Authentication through the single origin

```
Browser  ->  PUBLIC_APP_ORIGIN/auth/login
         ->  303 to the OIDC provider (authorization code + PKCE S256)
         ->  PUBLIC_APP_ORIGIN/auth/callback?code=…&state=…
         ->  server-side token exchange, ID-token validation, session issued
         ->  Set-Cookie: <session> (HttpOnly, SameSite=Lax, Path=/)
         ->  303 to AUTH_POST_LOGIN_PATH  (same origin, fixed)
         ->  the product frontend decides what to render
```

Nothing in this flow changed with ADR-0024 except where the callback
arrives. Still true, and still enforced: PKCE is mandatory, the redirect
URI is a single allowlisted value the browser never chooses, the session is
an `HttpOnly` cookie (never `localStorage`, never a URL), and no access
token is exposed to frontend code.

The identity provider is a **different** origin by design (locally
`http://zitadel.localhost:8081`; in this repository's production reference
topology an operator-controlled subdomain). ZITADEL has no supported
path-prefix deployment model — see ADR-0023 — so the authorization-redirect
leg changes host. Only the application itself is single-origin.

## Local vs production

The local edge is **development composition, not a production edge**. It
terminates no TLS, requests no certificate, and serves one plaintext
listener meant for `127.0.0.1`.

| | Local | Production (this repository's reference deployment) |
|---|---|---|
| Configuration | `infra/edge/assets/Caddyfile.local-edge` (packaged) | repository-root `Caddyfile` |
| Composition | `docker-compose.yml`'s `edge` | `docker-compose.prod.yml`'s `proxy` |
| TLS | none | ACME/automatic HTTPS, TLS 1.2+, HSTS |
| `/healthz`, `/readyz` | proxied to the backend | deliberately not proxied |
| Published ports | edge + developer escape hatches | the proxy only |
| `PUBLIC_APP_ORIGIN` | set in `.env` | set by the compose file as `https://${PUBLIC_DOMAIN}` |

A downstream product designs its own production edge. SaaS-OS standardizes
the local runtime boundary and does not assume a deployment provider —
production edge composition for consuming projects is deliberately not
standardized (ADR-0024).

## Troubleshooting

- **`AuthConfigurationError` mentioning PUBLIC_APP_ORIGIN and
  OIDC_REDIRECT_URI** — both are set and disagree. Unset one; normally that
  means deleting `OIDC_REDIRECT_URI`.
- **The provider rejects the callback** — the local ZITADEL application was
  bootstrapped against a different redirect URI, and an existing
  application's registered URI is never modified by the bootstrap. Edit it
  in the ZITADEL console, or `docker compose down -v` and re-bootstrap (a
  new `OIDC_CLIENT_ID` is printed).
- **A frontend route returns a backend 404** — the path collides with
  `/auth/*` or `/v1/*`. Those two prefixes are the backend's; pick another.
- **`PUBLIC_APP_ORIGIN` rejected at startup** — it must be an origin only.
  A path (`…/app`), a query string, a fragment or embedded credentials are
  all refused, and `http://` is refused when `ENVIRONMENT=production`.
