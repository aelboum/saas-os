# Local self-hosted identity (ADR-0023 Phase 1)

Development-only. `docker compose up` now runs a real, local, self-hosted
ZITADEL instance -- no ZITADEL Cloud account or other external OIDC
provider is required to exercise the login flow locally. See
`docs/ADR/0023-self-hosted-provider-neutral-identity-invisible-zitadel.md`
for the target architecture this is Phase 1 of; production self-hosting
(private network, Caddy path-proxy) is a later phase, not this one.

## Start the stack

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

## What's running

- `zitadel` -- the identity provider itself, reachable at
  `http://zitadel.localhost:8081` from both your browser and any
  container (see "Why `zitadel.localhost`" below). Admin console:
  `http://zitadel.localhost:8081/ui/console`, login
  `ZITADEL_FIRSTINSTANCE_ADMIN_USERNAME`/`_PASSWORD` from `.env`.
- `zitadel-db` -- ZITADEL's own dedicated PostgreSQL, entirely separate
  from SaaS-OS's own `db` service/database/credentials/migrations
  (ADR-0023 S5 -- ZITADEL manages its own schema; it must never join
  SaaS-OS's Alembic history).
- `zitadel-bootstrap` -- a one-shot container
  (`local-dev/bootstrap_zitadel.py`) that creates the `saas-os` project
  and `saas-os-backend` OIDC application via ZITADEL's own Management API,
  using a bootstrap machine user's Personal Access Token that ZITADEL
  itself generates at first startup. Safe to re-run (list-before-create by
  name); prints its result to `docker compose logs zitadel-bootstrap`.

`backend`/`worker` are not made to wait on `zitadel` at startup --
`core/identity`'s own OIDC discovery is resolved lazily on the first
`/auth/login` request, not at process startup.

## Why `zitadel.localhost`

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

## Resetting

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

## Master key

`ZITADEL_LOCAL_MASTERKEY` (`.env`) must be exactly 32 characters --
`openssl rand -hex 16` produces one. ZITADEL uses it to encrypt data at
rest; changing or losing it after first startup makes that instance's
already-encrypted data permanently unreadable. Since this instance is
local and disposable, the practical consequence of losing track of it is
just `docker compose down -v` and starting over -- not a production
incident.

## This is development-only

None of `zitadel`, `zitadel-db`, `zitadel-bootstrap-vol-init`,
`zitadel-bootstrap` exist in `docker-compose.prod.yml`. Production
self-hosting (private network, no host-published ZITADEL port, Caddy
path-proxy under the product's own domain) is a separate, later phase --
see ADR-0023.
