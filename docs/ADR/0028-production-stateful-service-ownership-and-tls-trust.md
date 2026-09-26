# ADR-0028: Production stateful-service ownership and TLS trust

Status: Accepted
Date: 2026-09-26
Supersedes / Superseded by: — (resolves the follow-up `docs/ADR/0021-database-redis-transport-encryption.md` deferred; does **not** reverse it)

## Context

ADR-0021 established a fail-closed application-side boundary: under
`ENVIRONMENT=production`, PostgreSQL must carry an encrypting `sslmode` and
Redis must use the `rediss://` scheme. It evaluated and **rejected** its own
Option C — provisioning TLS certificates for the bundled
`postgres:16-alpine`/`redis:7-alpine` services — and recorded the
consequence as an accepted Residual Limitation: as shipped,
`docker compose -f docker-compose.prod.yml up` cannot produce a healthy
`backend`/`worker`, because those stock services carry no TLS material. It
named the remedy without choosing it: *"A real deployment must point
`DATABASE_URL`/`REDIS_URL` at a TLS-capable endpoint (a managed cloud
database/cache, or an operator-provisioned certificate on these same
containers) before going to production."*

ADR-0027 then built disposable TLS validation infrastructure and proved, at
runtime, that the application behaves correctly against TLS-protected
PostgreSQL and Redis. It was explicit that this validates the *application*,
not the shipped topology, and it left four questions open.

Two facts must not be collapsed, and this ADR exists partly to keep them
apart:

```
Tier 2 validation  →  the application works correctly against TLS endpoints
docker-compose.prod.yml  →  still ships stock, non-TLS PostgreSQL and Redis
```

A deployment-gap audit against `main` (4d88db3) established the following by
reading and exercising the merged code, not by inference:

- PostgreSQL: `infra/db/config.py` classifies `require`, `verify-ca` and
  `verify-full` all as strong modes and returns a URL **unchanged** when one
  is already present. Verified empirically:
  `…?sslmode=verify-full&sslrootcert=/ca/rds.pem` survives intact, other
  libpq query parameters included; a bare URL has `sslmode=require`
  injected; `sslmode=disable` raises `DatabaseConfigurationError`.
- Migrations: `infra/db/migrations/env.py::_get_url()` returns
  `get_migrations_database_config().url`, so `MIGRATIONS_DATABASE_URL` gets
  identical enforcement and can address an external endpoint.
- Redis: `infra/jobs/config.py` and `infra/ratelimit/config.py` validate the
  scheme only. There is **no** `ssl_ca_certs`/`ssl_cert_reqs`/
  `ssl_check_hostname` surface anywhere in `infra/`, `api/` or `core/`, and
  no in-URL equivalent to `sslrootcert`. Certificate verification is
  nonetheless enforced because the resolved `redis-py` 5.3.1 defaults
  `SSLConnection.cert_reqs` to `CERT_REQUIRED`
  (`tests/infra/jobs/test_redis_tls_client_defaults_unit.py` pins this,
  since `pyproject.toml` declares `redis>=5.0`, a floor).
- Configuration: both URLs are read through
  `get_secrets_provider().get(...)`; under `ENVIRONMENT=production` the
  provider is `EnvironmentSecretsProvider`, reading the process environment.
  Any mechanism that populates the container environment therefore works —
  no new secrets provider is needed to carry an external endpoint.
- Backup: `infra/db/backup.create_backup(*, container: str, …)` takes a
  mandatory container name and runs `pg_dump`/`pg_restore` through
  `docker exec`, deliberately so that no `postgresql-client` dependency
  exists anywhere and the connection uses the container's own loopback.

## Decision

**Accepted.** Four decisions, recorded together because they are coupled.

### D1 — Production PostgreSQL and Redis are operator-managed, external, TLS-capable endpoints (Option A)

A production deployment supplies `DATABASE_URL`, `MIGRATIONS_DATABASE_URL`
and `REDIS_URL` pointing at stateful services it owns and certificates it
manages. SaaS-OS does not provision, certificate or rotate them.

This **does not reverse ADR-0021**. ADR-0021 rejected provisioning TLS for
the bundled services (its Option C) and named a managed database/cache as a
sanctioned answer; this decision selects that answer. Option C remains
rejected and would still require its own ADR to revisit.

**Implemented in `docker-compose.prod.yml`:** the shipped `db` and `redis`
services are **development/local convenience services, not mandatory
production dependencies**. They now carry `profiles: ["bundled-stateful"]`,
so a production `docker compose -f docker-compose.prod.yml up` does not
start them, and `backend`/`worker` no longer declare `depends_on` on them —
`backend` has no `depends_on` at all. They remain the correct subject of
`scripts/check-docker-prod.sh`'s perimeter test, which starts them
explicitly by name; Compose starts an explicitly named service even when it
carries a profile, so that script needs no change. Local development is
unaffected: it uses `docker-compose.yml`'s own `db`/`redis`, which were not
touched.

Why not Option B (TLS-enable the bundled services): it is ADR-0021's
rejected Option C, and it requires a CA plus per-service certificates,
`ssl=on` with cert/key paths for PostgreSQL, `--tls-port`/`--tls-cert-file`
for Redis, key ownership (uid 70 / 999) at mode 0600, persistent certificate
storage, startup ordering so certificates exist before the services boot,
TLS-aware health checks, and a rotation story — a certificate-management
project SaaS-OS has repeatedly declined to own. ADR-0027's harness
demonstrates it is achievable as *disposable validation* infrastructure;
that is not an argument for shipping it.

Why not Option C (hybrid — one external, one bundled): mechanically
supported, since the two URLs are independent, but it inherits the backup
constraint (D4) and the Redis trust problem (D3) at the same time, for no
compensating benefit. Reconsider only if a specific hosting reality forces
it.

Portability: this decision moves SaaS-OS toward, not away from, the
deployment-target interface `docs/DEPLOYMENT-ARCHITECTURE.md` §7 already
requires — an application that addresses its stateful services purely by URL
is the precondition for a future Kubernetes or managed-platform target.

### D2 — Production PostgreSQL uses `verify-full`

`verify-full` is the recorded production target: encryption plus CA
verification plus hostname verification.

It **requires no application-code change** — this was verified against the
merged code, not assumed. `infra/db/config.py` already treats it as a strong
mode and leaves it, and its `sslrootcert` parameter, untouched.

The runtime default is **not** changed by this ADR. `_REQUIRED_SSLMODE_DEFAULT`
remains `require`, which is what gets injected when an operator supplies no
`sslmode`. `verify-full` is reached by the operator writing it into the URL,
not by SaaS-OS silently escalating — escalating the default would fail
closed for every existing deployment that has no CA distributed yet.

Operational requirements, all operator-owned:

- a CA certificate readable by every connecting container, referenced as
  `?sslmode=verify-full&sslrootcert=<path>`;
- the server certificate's SAN must match the hostname used in the URL;
- `MIGRATIONS_DATABASE_URL` must carry equivalent TLS configuration —
  migrations run through the same enforcement path and are not exempt;
- a rotation process, since an expired or replaced CA breaks connections;
- understood failure behaviour: an invalid or untrusted certificate fails
  the connection closed. There is no fallback to `require`, and
  `infra/db/config.py` will not weaken an operator's explicit choice.

`require` remains valid and is the correct interim mode for a deployment
that does not yet have CA distribution solved. `verify-ca` is a legitimate
intermediate step where hostname matching is impractical.

### D3 — Redis trust: prefer a publicly trusted endpoint (D3-A); a combined `SSL_CERT_FILE` bundle (D3-B) is the sanctioned fallback

Redis is **not** symmetric with PostgreSQL and this ADR does not pretend
otherwise. Current, verified behaviour:

```
rediss://                → TLS transport
certificate verification → CERT_REQUIRED (redis-py client default)
hostname verification    → OFF, and not configurable
```

Redis therefore does **not** provide `verify-full` semantics today, and no
wording in SaaS-OS documentation may imply that it does.

- **D3-A (selected preference): a publicly trusted Redis certificate.** No
  private CA distribution, nothing to rotate inside SaaS-OS, and the client
  default already verifies the chain. Typical of managed cache offerings and
  consistent with D1.
- **D3-B (sanctioned fallback): a combined process trust store.** Because
  `redis-py` builds its context with `ssl.create_default_context()`,
  OpenSSL's default verify paths apply and `SSL_CERT_FILE` is honoured.
  Note the collision an implementation must respect: `backend` already sets
  `SSL_CERT_FILE: /identity-ca/tls.crt` for ZITADEL, so trusting a private
  Redis CA on `backend` means supplying **one combined bundle** at that
  single variable, never a second variable. `worker` sets no `SSL_CERT_FILE`
  and is unconstrained. This is a process-wide grant: the CA becomes trusted
  for every TLS connection that container makes, which is precisely why it
  is the fallback and not the preference.
- **D3-C (not adopted): an application-level `ssl_ca_certs` surface.**
  `arq`'s `RedisSettings` exposes `ssl_ca_certs`, `ssl_cert_reqs`,
  `ssl_ca_data` and `ssl_check_hostname`, so this is implementable — but it
  is a code change to `infra/jobs/config.py` and `infra/ratelimit/config.py`,
  the exact modules ADR-0021 fixed, and it would be the natural home for
  enabling hostname verification too. Deferred, not rejected: revisit it if
  D3-A proves unavailable and D3-B's process-wide trust is judged too broad.

Under no option may certificate verification be disabled. `CERT_NONE`,
`ssl_cert_reqs=none` and equivalent bypasses are out of bounds, and the
existing regression test exists to catch a dependency bump that would
weaken the default.

### D4 — External PostgreSQL support is a production requirement, so D4-B is required

D1 makes this unavoidable rather than a footnote. The current transport is:

```
backup process → docker exec → PostgreSQL container
```

That works for a bundled database and has real merits — no
`postgresql-client` dependency anywhere, and the connection uses the
container's loopback, which also means the backup path never traverses TLS.
It has no meaning for a managed database: there is no container to exec
into. `create_backup()`'s mandatory `container` argument makes this a
structural coupling, not a configuration detail.

**Decision:** keep the existing container transport (D4-A) as-is for bundled
and local use, and require a second, endpoint-based path (D4-B) before any
production deployment on external PostgreSQL is considered complete.

**D4-B is now implemented** (`infra/db/backup`): `create_backup()` and
`restore_backup()` take `container` as optional. Passing it keeps the
unchanged `docker exec` transport; omitting it runs `pg_dump`/`pg_restore`
(and the `CREATE DATABASE` step's `psql`) directly against the endpoint the
supplied `DatabaseConfig` names. TLS is *forwarded, never decided*: the
`sslmode`/`sslrootcert`/`sslcert`/`sslkey` already resolved by
`infra/db/config.py` are passed through libpq's own `PGSSL*` environment
variables, so an operator's `verify-full` reaches the client intact and is
never rewritten to `require`, and there is no plaintext fallback. Neither
the password nor any connection string is ever an argv element. No vendor
or managed backup service is selected by this ADR.

The remaining requirement is operational, not architectural: the endpoint
transport needs the PostgreSQL client binaries (`pg_dump`, `pg_restore`,
`psql`) on whatever host executes backups — deliberately *not* added as a
repository dependency, since the container transport still needs none. A
missing binary produces an actionable error naming the tool and the
alternative transport, rather than an opaque `FileNotFoundError`.

## Decision coupling

```
D1 service ownership  (external, operator-managed)
        │
        ├── D2 PostgreSQL TLS verification   → verify-full, already supported
        │
        ├── D3 Redis trust                   → D3-A preferred, D3-B fallback
        │
        └── D4 backup transport              → D4-B becomes REQUIRED
```

D1 is the root. Selecting external services makes D2 achievable immediately
at no code cost, makes D3 a live question whose answer depends on the
endpoint the operator chooses, and converts D4 from a deferred curiosity
into a prerequisite. D4 is the only one of the three that requires SaaS-OS
code to change.

## Future implementation (none of this exists yet)

Recorded so that no reader mistakes decision for delivery:

1. `docker-compose.prod.yml`: make `db`/`redis` opt-in and remove
   `backend`/`worker`'s `depends_on` on them, so an external deployment does
   not start unused stateful services. **Done** — via
   `profiles: ["bundled-stateful"]`.
2. An operator runbook: required `DATABASE_URL`/`MIGRATIONS_DATABASE_URL`/
   `REDIS_URL` shapes, the CA mount, and rotation ownership. **Not done.**
3. D4-B, the endpoint-based backup path. **Done** — `infra/db/backup`,
   covered by `tests/infra/db/test_backup_endpoint_transport_unit.py`.
4. Optionally D3-C, if D3-A and D3-B both prove unsuitable. **Not done.**

No change to `infra/db/config.py`, `infra/jobs/config.py` or
`infra/ratelimit/config.py` is required for D1 or D2.

## Operational responsibilities (outside SaaS-OS)

Provisioning the PostgreSQL and Redis endpoints; issuing, distributing and
rotating their certificates; the CA trust material referenced by
`sslrootcert` or by a combined `SSL_CERT_FILE` bundle; endpoint credentials;
and installing the PostgreSQL client binaries on the host that executes
backups (see D4).

## Non-goals

- No reversal of ADR-0021; its Option C stays rejected.
- No change to the `sslmode` default, to Redis hostname-verification
  behaviour, or to any fail-closed default.
- No Redis CA configuration surface added.
- No change to `docker-compose.prod.yml`, `infra/db/backup`, or production
  secrets handling.
- No vendor selection, certificate creation, or deployment.

## Related

`docs/ADR/0021-database-redis-transport-encryption.md` (the boundary this
follows up, and the Residual Limitation this resolves);
`docs/ADR/0027-production-validation-tls-infrastructure.md` (the validation
that proved the application side, and the source of D1–D4);
`docs/ADR/0010-deployment-target.md` (the Docker Compose + VPS target the
current backup transport assumes);
`docs/DEPLOYMENT-ARCHITECTURE.md` (the three-way distinction between
reference, operator-provided and validation infrastructure).
