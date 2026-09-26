# Local self-hosted identity (ADR-0023 Phase 1)

Development-only. `docker compose up` runs a real, local, self-hosted
ZITADEL instance -- no ZITADEL Cloud account or other external OIDC
provider is required to exercise the login flow locally. See
`docs/ADR/0023-self-hosted-provider-neutral-identity-invisible-zitadel.md`
for the target architecture this is Phase 1 of; production self-hosting
is covered separately (see "This is development-only" at the end).

This document has two audiences:

- **[SaaS-OS repository development](#saas-os-repository-development)** --
  working on SaaS-OS itself, in this repository.
- **[Downstream product development](#downstream-product-development)** --
  a product that depends on SaaS-OS (ADR-0015) and wants the same local
  ZITADEL topology, without copying SaaS-OS files.

Both use the same tool: **`saas-os-local-identity`**, a console script
installed with the `saas-os` package (`infra/local_identity/zitadel_bootstrap.py`).

## SaaS-OS repository development

### Start the stack

```bash
cp .env.example .env   # first time only
docker compose up -d
docker compose logs zitadel-bootstrap
```

The last command prints a line like:

```
Set this in your .env (only if it changed):  OIDC_CLIENT_ID=392029046428401671
```

Copy that value into `.env`'s `OIDC_CLIENT_ID`, then
`docker compose up -d backend` to pick it up (only needed the first time,
or if you `docker compose down -v` and get a fresh instance).

The application is then served on a single origin -- `PUBLIC_APP_ORIGIN`,
`http://localhost:8080` by default (ADR-0024). That is the origin the OIDC
callback is derived from, so `OIDC_REDIRECT_URI` is normally not set at all.
See `docs/SINGLE-ORIGIN-RUNTIME.md` for the runtime itself.

### What's running

- `zitadel` -- the identity provider itself, reachable at
  `http://zitadel.localhost:8081` from both your browser and any
  container (see "Why `zitadel.localhost`" below). Admin console:
  `http://zitadel.localhost:8081/ui/console`, login
  `ZITADEL_FIRSTINSTANCE_ADMIN_USERNAME`/`_PASSWORD` from `.env`.
- `zitadel-db` -- ZITADEL's own dedicated PostgreSQL, entirely separate
  from SaaS-OS's own `db` service/database/credentials/migrations
  (ADR-0023 S5 -- ZITADEL manages its own schema; it must never join
  SaaS-OS's Alembic history).
- `zitadel-bootstrap` -- a one-shot container running
  `saas-os-local-identity` from the `backend` image. It creates the
  `saas-os` project and `saas-os-backend` OIDC application (the defaults;
  see "Configuration reference" below) via ZITADEL's own Management API,
  using a bootstrap machine user's Personal Access Token that ZITADEL
  itself generates at first startup. Safe to re-run (list-before-create by
  name); prints its result to `docker compose logs zitadel-bootstrap`.
  (`local-dev/bootstrap_zitadel.py` remains as a thin compatibility
  entrypoint that delegates to the same packaged code -- the production
  bootstrap wrapper loads it by path.)
- `edge` -- the single-origin application edge (ADR-0024). Not part of the
  identity topology, but the reason `http://localhost:8080/auth/login`
  works: it routes `/auth/*` to `backend` and everything else to
  `frontend`. See `docs/SINGLE-ORIGIN-RUNTIME.md`.

`backend`/`worker` are not made to wait on `zitadel` at startup --
`core/identity`'s own OIDC discovery is resolved lazily on the first
`/auth/login` request, not at process startup.

### Why `zitadel.localhost`

`OIDC_ISSUER_URL` (SaaS-OS's own provider-neutral config, docs/ADR/0023-...
Phase 2) has to be one single URL that works both for your
browser (the OIDC authorization-redirect leg is a real browser navigation)
and for `backend`'s own server-side calls (discovery, token exchange) --
and separately, for `zitadel-bootstrap`'s Management API calls. ZITADEL
resolves *which instance* a request belongs to by matching the request's
`Host` header against its configured external domain, not by network path
-- so a container calling ZITADEL by its Docker service name alone (a
different Host header) gets a 404, not a routing pass-through.
`zitadel.localhost` is the fix: the reserved `.localhost` TLD (RFC 6761)
resolves to `127.0.0.1` on your machine with no `/etc/hosts` entry needed,
and `docker-compose.yml` gives the `zitadel` service that exact same
string as a Docker network alias -- so it's one identical, correctly
Host-matching URL from every direction.

### Resetting

```bash
docker compose down -v
```

destroys the local ZITADEL instance (its Postgres data, encryption
material, the admin/bootstrap accounts, the OIDC application) along with
everything else `-v` removes. `docker compose up` after that runs a fully
fresh `ZITADEL_FIRSTINSTANCE_*` bootstrap and `zitadel-bootstrap` creates a
new OIDC application with a new `OIDC_CLIENT_ID` -- copy the newly
printed value into `.env` again.

`docker compose down` (no `-v`) and back `up` preserves everything;
`zitadel-bootstrap` recognizes the existing project/application and reuses
the same `OIDC_CLIENT_ID`, no `.env` change needed.

### Master key

`ZITADEL_LOCAL_MASTERKEY` (`.env`) must be exactly 32 characters --
`openssl rand -hex 16` produces one. ZITADEL uses it to encrypt data at
rest; changing or losing it after first startup makes that instance's
already-encrypted data permanently unreadable. Since this instance is
local and disposable, the practical consequence of losing track of it is
just `docker compose down -v` and starting over -- not a production
incident.

## Downstream product development

A product that depends on SaaS-OS (pinned Git dependency, ADR-0015) can run
the same local ZITADEL topology. What it reuses and what it owns:

| Reused from the installed `saas-os` package | Owned by the product's own repository |
|---|---|
| `saas-os-local-identity` -- the bootstrap tool (project + public PKCE application, idempotent, prints `OIDC_CLIENT_ID`) | Its own `docker-compose.yml` services for `zitadel-db`, `zitadel`, and the one-shot `zitadel-bootstrap` |
| The provider-neutral OIDC relying party (`core/identity`, `api/auth`) its backend already uses | Its own `.env`: project/application names, `PUBLIC_APP_ORIGIN`, `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID` |
| `saas-os-edge-config` -- the reusable single-origin edge configuration (ADR-0024, `docs/SINGLE-ORIGIN-RUNTIME.md`), which is also what derives the callback from `PUBLIC_APP_ORIGIN` | Its own frontend, backend, product routes and authenticated entry point |

No SaaS-OS Python source is copied: the product's backend image already has
`saas-os` installed, so the `saas-os-local-identity` command is already on
its `PATH`. SaaS-OS does **not** ship a reusable Compose fragment for the
*identity* services -- they are plain configuration of third-party images
(`ghcr.io/zitadel/zitadel`, `postgres`, `busybox`), which the product
declares in its own Compose file, modelled on this repository's
`docker-compose.yml` (a one-time copy of configuration the product then
owns, like any scaffold -- ADR-0015 rules 9/10 -- not an ongoing
dependency). The product never calls ZITADEL's APIs from its own code
(ADR-0023 §2 requirement 4); the bootstrap is SaaS-OS tooling.

The single-origin *edge* configuration is different, and is shipped:
it encodes SaaS-OS's own route surface (`/auth/*`, `/v1/*`), which evolves
with SaaS-OS rather than with a third-party image, so a product obtains it
from its installed dependency with `saas-os-edge-config` instead of
re-deriving it (ADR-0024 rule 5). See `docs/SINGLE-ORIGIN-RUNTIME.md`.

### Required configuration

In the product's `.env`:

```bash
# Names of the local ZITADEL project/application. Product-chosen, non-secret.
OIDC_LOCAL_PROJECT_NAME=my-product
OIDC_LOCAL_APPLICATION_NAME=my-product-backend

# The single browser-visible origin the product is served on (ADR-0024).
# The bootstrap registers the callback derived from it
# (<origin>/auth/callback) -- the same derivation the backend performs
# (api/auth/config.py), so there is one source of truth. Set
# OIDC_REDIRECT_URI instead only for a callback that is not on this origin.
PUBLIC_APP_ORIGIN=http://localhost:8080
SAAS_OS_EDGE_PORT=8080

# Issuer: http://zitadel.localhost:<ZITADEL_LOCAL_PORT>, see below.
OIDC_ISSUER_URL=http://zitadel.localhost:8081
OIDC_CLIENT_ID=            # filled in from the bootstrap output
OIDC_CLIENT_SECRET=        # always empty: public PKCE client

# ZITADEL server configuration, as in SaaS-OS's .env.example.
ZITADEL_LOCAL_PORT=8081
ZITADEL_LOCAL_MASTERKEY=   # exactly 32 characters: openssl rand -hex 16
ZITADEL_DB_USER=zitadel
ZITADEL_DB_PASSWORD=...
ZITADEL_DB_NAME=zitadel
ZITADEL_FIRSTINSTANCE_ADMIN_USERNAME=admin
ZITADEL_FIRSTINSTANCE_ADMIN_PASSWORD=...
ZITADEL_FIRSTINSTANCE_ADMIN_EMAIL=...
```

### Compose services

Take `zitadel-db`, `zitadel-bootstrap-vol-init`, and `zitadel` from this
repository's `docker-compose.yml` as they are (their comments explain every
setting; set `ZITADEL_FIRSTINSTANCE_ORG_NAME` to whatever the product
likes). The requirements that must be kept, because the bootstrap and the
issuer check depend on them:

- `ZITADEL_EXTERNALDOMAIN: zitadel.localhost`, `ZITADEL_PORT` and
  `ZITADEL_EXTERNALPORT` both `${ZITADEL_LOCAL_PORT}`, published as
  `"${ZITADEL_LOCAL_PORT}:${ZITADEL_LOCAL_PORT}"`, and the network alias
  `zitadel.localhost` (see "Why `zitadel.localhost`").
- The machine user + PAT (`ZITADEL_FIRSTINSTANCE_ORG_MACHINE_*`,
  `ZITADEL_FIRSTINSTANCE_PATPATH: /bootstrap/bootstrap.pat`) on a volume
  shared with the bootstrap service.
- `ZITADEL_DEFAULTINSTANCE_FEATURES_LOGINV2_REQUIRED: "false"`.

The bootstrap service then runs the product's own backend image:

```yaml
  zitadel-bootstrap:
    build: .                       # the product's backend image (has saas-os installed)
    entrypoint: ["saas-os-local-identity"]
    environment:
      ZITADEL_INTERNAL_URL: http://zitadel.localhost:${ZITADEL_LOCAL_PORT}
      PUBLIC_APP_ORIGIN: ${PUBLIC_APP_ORIGIN}
      OIDC_LOCAL_PROJECT_NAME: ${OIDC_LOCAL_PROJECT_NAME}
      OIDC_LOCAL_APPLICATION_NAME: ${OIDC_LOCAL_APPLICATION_NAME}
    volumes:
      - zitadel-bootstrap:/bootstrap:ro
    depends_on:
      zitadel:
        condition: service_healthy
```

### Startup sequence

```bash
docker compose up -d
docker compose logs zitadel-bootstrap
```

`zitadel-db` becomes healthy, `zitadel-bootstrap-vol-init` fixes the
shared volume's permissions, `zitadel` runs `start-from-init` (writing the
PAT) and becomes healthy, then `zitadel-bootstrap` creates (or finds) the
product's project and application and prints:

```
Local ZITADEL OIDC application ready (project 'my-product', application 'my-product-backend').
Redirect URI: http://localhost:8080/auth/callback
Set this in your .env (only if it changed):  OIDC_CLIENT_ID=392029046428401671
```

Copy that `OIDC_CLIENT_ID` into the product's `.env` and restart its
backend. The client id is assigned by ZITADEL, so it is never committed:
it only changes when the ZITADEL volumes are destroyed
(`docker compose down -v`). Resetting and idempotency behave exactly as
described above for SaaS-OS itself.

The tool can also be run outside Compose (e.g. from a virtualenv with
`saas-os` installed), provided `zitadel.localhost:<port>` is reachable and
the PAT file is readable: `saas-os-local-identity --pat-path ./bootstrap.pat`
(see `--help`).

## Configuration reference

`saas-os-local-identity` reads environment variables; each has a CLI flag
that takes precedence. An empty value counts as unset.

| Variable | Flag | Default | Meaning |
|---|---|---|---|
| `ZITADEL_INTERNAL_URL` | `--zitadel-url` | *(required)* | ZITADEL's URL as reachable from the tool -- must use the same host:port as the issuer (`http://zitadel.localhost:<ZITADEL_LOCAL_PORT>`) |
| `PUBLIC_APP_ORIGIN` | `--public-app-origin` | *(none)* | The browser-visible application origin; the registered redirect URI is derived from it as `<origin>/auth/callback` (ADR-0024) |
| `OIDC_REDIRECT_URI` | `--redirect-uri` | `http://localhost:8000/auth/callback` | Registered redirect URI, for a callback that is not on the application origin -- the same variable the backend reads. Set together with `PUBLIC_APP_ORIGIN` it must agree with the derived value, or the tool fails closed |
| `OIDC_LOCAL_PROJECT_NAME` | `--project-name` | `saas-os` | ZITADEL project name |
| `OIDC_LOCAL_APPLICATION_NAME` | `--application-name` | `saas-os-backend` | ZITADEL application name |
| `ZITADEL_BOOTSTRAP_PAT_PATH` | `--pat-path` | `/bootstrap/bootstrap.pat` | PAT file written by ZITADEL (`ZITADEL_FIRSTINSTANCE_PATPATH`) |

Behavior, whatever the names:

- **Client type**: always a public OIDC web application -- authorization
  code grant, `authMethodType` NONE (no client secret), PKCE (S256
  enforced by `core/identity`). `OIDC_CLIENT_SECRET` stays empty.
- **Idempotency**: projects and applications are listed and matched by
  exact name before anything is created. Re-running never duplicates a
  project or application and returns the same `OIDC_CLIENT_ID`. The tool
  never creates organizations -- it uses the instance's default
  organization, which ZITADEL itself creates at first-instance setup.
  Different names in one instance give independent projects/applications.
- **Existing applications are not modified**: if the application already
  exists, its registered redirect URI is left as it is. After changing
  `OIDC_REDIRECT_URI`, edit it in the ZITADEL console, or reset the
  instance.
- **Readiness**: every Management API call is retried (15 attempts, 2 s
  apart) to cover ZITADEL's projections lagging just after it reports
  healthy; after that the tool fails with a non-zero exit.
- **Secrets**: the PAT is read from the shared volume and never printed or
  stored elsewhere. Nothing is written to any file.

## This is development-only

None of these services are shared with `docker-compose.prod.yml` --
production defines its own `zitadel`/`zitadel-db`/`zitadel-bootstrap`
(private networks, no host-published ZITADEL port, ZITADEL served at the
root of its own public domain -- never under a path prefix, which ZITADEL's
own reverse-proxy documentation does not support). Which domain that is
depends on the ADR-0025 deployment profile: the application's own
`PUBLIC_DOMAIN` in the fresh profile, or an operator-controlled identity
subdomain fronted by its own Caddy site block in the existing profile. See
docs/DEPLOYMENT-ARCHITECTURE.md §11a, docs/RUNBOOKS.md's own
"Self-hosted identity operations" section, ADR-0023 and ADR-0025.

`saas-os-local-identity` is development tooling. SaaS-OS does not provision
identity infrastructure for arbitrary production deployments: a downstream
product designs its own production identity deployment (ADR-0023,
"Downstream product contract and compatibility"). The only production use
of this code is SaaS-OS's own reference topology
(`docker-compose.prod.yml`), whose wrapper
(`deploy/bootstrap_zitadel_production.py`) runs it with the default names.
