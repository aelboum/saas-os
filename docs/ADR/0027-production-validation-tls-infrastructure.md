# ADR-0027: Disposable TLS validation infrastructure for full production validation

Status: Accepted
Date: 2026-09-26
Supersedes / Superseded by: — (complements `docs/ADR/0021-database-redis-transport-encryption.md`; does not reverse it)

## Context

ADR-0021 established a fail-closed application-side transport-encryption
boundary: under `ENVIRONMENT=production`, `infra/db/config.py` requires an
encrypting `sslmode` and `infra/jobs/config.py`/`infra/ratelimit/config.py`
require the `rediss://` scheme. `docker-compose.prod.yml` sets
`ENVIRONMENT: production` on `backend`/`worker` and deliberately ships no
plaintext opt-out.

That ADR also considered, and **rejected**, provisioning TLS certificates for
its own stock `postgres:16-alpine`/`redis:7-alpine` services (its Option C),
on the grounds that a certificate-management story is a materially larger
project than a configuration boundary. It recorded the consequence as an
accepted Residual Limitation: as shipped, those two services carry no TLS
material, so `backend`/`worker` cannot become healthy against them, and
`scripts/check-docker-prod.sh` therefore stops at the backend/worker step.
It named the follow-up explicitly: *"updating that script (or supplying it a
TLS-capable database/cache) is a follow-up outside this ADR's scope."*

This ADR is that follow-up, and only that follow-up.

The practical problem it solves: there was no way to answer "does the SaaS-OS
production application stack actually work against TLS-protected PostgreSQL
and Redis?" with runtime evidence. Every previous attempt either stopped at
the migration step or was tempted toward a dishonest shortcut — disabling
TLS, setting `DB_REQUIRE_TLS=false`, or pointing the application at one
service while reporting another's health.

## Decision

**Accepted.** Full production validation of the SaaS-OS application stack
uses a **disposable, TLS-capable PostgreSQL and Redis validation
environment**, provisioned per run, entirely outside the shipped reference
Compose stateful services.

Concretely, `scripts/check-docker-prod-tls.sh`:

1. generates a per-run PKI and a Compose override file in a temporary
   directory outside this repository;
2. layers that override onto the unmodified `docker-compose.prod.yml` with
   `-f`, adding `valdb` (PostgreSQL with `ssl=on`) and `valredis` (Redis with
   `--tls-port`, plaintext `--port 0`);
3. repoints `backend`/`worker` at those endpoints and replaces their
   `depends_on` with `!override` so the stock services cannot be pulled in;
4. runs the production migration path, the real application containers, the
   real Caddy edge, and the real ZITADEL v4.19.0 / Login V2 v4.19.0 identity
   stack against them;
5. tears everything down, including the certificates, in a `trap`.

`docker-compose.prod.yml` is never edited. Nothing is added to the shipped
topology.

## Explicit distinction

This ADR's central point, and the reason it exists separately from ADR-0021:

```
Reference production Compose topology
        ≠
Full production validation infrastructure
```

- The **reference topology** (`docker-compose.prod.yml` with its stock
  `db`/`redis`) remains the right subject for perimeter and topology
  validation: which ports are published, which services are unreachable from
  outside, that TLS terminates at the proxy. `scripts/check-docker-prod.sh`
  keeps that job unchanged.
- The **validation infrastructure** exists solely to exercise the
  application's production TLS boundary. It is not a deployment
  recommendation, not a production topology, and is never shipped.

Neither script replaces the other, and neither may claim the other's
evidence.

## Honesty constraints (binding on the harness)

The failure mode this ADR exists to prevent is a fabricated hybrid — a run
that looks green because it validates something other than what it reports.
The harness must therefore never:

- start the stock `db`/`redis` while the application connects elsewhere;
- describe the stock services as the TLS infrastructure;
- run the backup check against a database the application did not use;
- assert one service's connectivity while reporting another's health;
- leave unused TLS-disabled services in the validation topology where their
  presence would make the result ambiguous.

**The endpoints the application connects to are the endpoints validated and
reported.** The harness asserts this structurally against the rendered
configuration before starting anything, rather than relying on review.

## Redis trust

Redis is the constraint that shapes this design, and it is not symmetric
with PostgreSQL (see ADR-0021's corrected Context). For the resolved
`redis-py` 5.3.1, `SSLConnection` builds its context with
`ssl.create_default_context()` and sets `ssl_cert_reqs="required"` — a
`rediss://` connection verifies the server certificate. This repository
exposes no application-level `ssl_ca_certs` surface and this ADR does not add
one.

**Mechanism chosen: the validation CA is trusted through the client's own
trust store, via `SSL_CERT_FILE`.** Because redis-py uses
`ssl.create_default_context()`, OpenSSL's default verify paths apply, and
those honour `SSL_CERT_FILE`/`SSL_CERT_DIR`. The harness points
`SSL_CERT_FILE` at a bundle containing both the validation CA and ZITADEL's
own identity CA (which `backend` already trusts through the same variable),
supplied on a read-only volume to `backend`/`worker` only.

This satisfies every constraint required of it:

- **disposable** — the bundle lives in a per-run volume, destroyed with the
  project;
- **generated per run** — a fresh CA each time, with its private key
  discarded once the leaf certificates are issued;
- **outside the repository** — generated into a temp directory and a Docker
  volume; nothing is written into the working tree;
- **never disables verification** — `ssl_cert_reqs` is untouched;
  `CERT_NONE`, `ssl_cert_reqs=none` and `check_hostname=False` overrides do
  not appear in the harness, and `tests/infra/jobs/test_redis_tls_client_defaults_unit.py`
  regression-tests the client default;
- **introduces no production configuration surface** — `SSL_CERT_FILE` is an
  OpenSSL environment variable the reference deployment already uses for the
  identity CA, not a new SaaS-OS setting;
- **grants no permanent trust** — the CA is never added to any image, any
  committed file, or any host trust store.

The harness additionally proves the verification is real by attempting the
same connection against a trust store that does *not* contain the validation
CA and requiring that attempt to fail.

Alternatives, and why not: a publicly trusted certificate needs a real DNS
name and issuance path, so it cannot serve a disposable local run; a new
`ssl_ca_certs` configuration surface would change the exact modules ADR-0021
fixed and is a production decision, not a validation one; baking the CA into
the application image would grant it authority over every TLS connection the
container makes and would require a Dockerfile change.

## PostgreSQL TLS

The validation PostgreSQL uses a **self-signed validation certificate**, and
the application keeps **`sslmode=require`** — unchanged from ADR-0021. The
harness deliberately sets no `sslmode` on the URL it supplies, so the run
proves `infra/db/config.py` injects `sslmode=require` itself rather than
pre-satisfying the check.

`sslmode=require` encrypts without verifying the server certificate or
hostname. That is a real, known limitation, stated plainly here rather than
glossed: this validation proves the transport is encrypted and that the
fail-closed boundary holds, **not** that the database's identity is
authenticated.

Moving production to `verify-ca` or `verify-full` would be a security
improvement and is the right eventual direction for this repository's
financial-services target, but it requires CA issuance, rotation and trust
distribution to every connecting container. **It is a separate future
production-security decision and is explicitly not made here.**

## Secrets

All validation credentials and certificates are generated into a temporary
directory outside the repository and a per-run Docker volume. They are
throwaway values, never real deployment secrets, and are destroyed on exit.
Nothing generated by a validation run may be committed; the repository's
existing `detect-secrets` gate remains the backstop.

## Disposal

| Resource | Name | Removed by |
|---|---|---|
| Compose project | `saas-os-tier2` | `docker compose ... down -v --remove-orphans` in the `trap` |
| Network | `saas-os-tier2_internal` (and the identity networks) | same |
| Volumes | `saas-os-tier2_val-certs`, plus the project's own data volumes | same (`-v`) |
| Certificates / override file | `$TMPDIR/saas-os-tier2.XXXXXX/` | `rm -rf` in the `trap` |

Cleanup runs from a `trap ... EXIT`, so it happens on success, on failure and
on interrupt alike. Diagnostics are captured *before* teardown when the run
did not fully pass. The harness removes only resources belonging to its own
uniquely named project; unrelated Docker resources are never touched.

## Backup

Candidate B keeps PostgreSQL containerized, so `infra/db/backup`'s existing
`docker exec` transport continues to work unchanged. **`infra/db/backup` is
not modified by this ADR.**

The harness points the backup check at the **validation** PostgreSQL
container, never at the unused stock `db` service — running backup against a
database the application never wrote to would be precisely the fabricated
hybrid this ADR forbids.

Whether that `docker exec` transport should remain the permanent backup
architecture is a separate question, relevant only if external stateful
infrastructure is ever adopted. This ADR does not decide it.

## Non-goals

Stated explicitly, because each was available and deliberately not taken:

- **No change to the shipped production Compose topology.** ADR-0021's
  Option C stays rejected; the stock `db`/`redis` remain uncertificated.
- **No change to PR #1.**
- **No production Redis CA configuration surface.**
- **No PostgreSQL `verify-ca`/`verify-full` migration.**
- **No external managed database adoption** (Candidate A), and no vendor
  selection.
- **No backup architecture redesign.**
- **No SaaS-OS application source, dependency or security-control changes.**
- **No weakening of any fail-closed default** — `DB_REQUIRE_TLS` and
  `REDIS_REQUIRE_TLS` are never set by the harness, so the production
  defaults are what gets exercised.

## Tests

`tests/infra/jobs/test_redis_tls_client_defaults_unit.py` pins the resolved
Redis client's TLS defaults (`cert_reqs == CERT_REQUIRED`, no implicit CA,
hostname checking off) and asserts that neither Redis-owning config module
configures a verification bypass. `pyproject.toml` declares `redis>=5.0`, a
floor rather than an exact pin, so this behaviour is a property of the
resolved dependency and must be regression-tested rather than assumed.

The 88 behavioural Caddy tests in
`tests/architecture/test_identity_proxy_routing.py` remain separate,
config-level evidence for the edge contract and are neither replaced nor
duplicated by this harness — they are faster, run without Docker, and cover
both identity profiles.

## Related

`docs/ADR/0021-database-redis-transport-encryption.md` (the boundary this
validates, and the Residual Limitation this follows up);
`docs/ADR/0024-single-origin-application-runtime.md` (the callback derivation
the harness asserts at runtime);
`docs/ADR/0025-same-origin-zitadel-login-v2-topology.md` (the identity
profile the harness runs);
`docs/DEPLOYMENT-ARCHITECTURE.md` (the three-way distinction between
reference, operator-provided and validation infrastructure);
`scripts/check-docker-prod.sh` (the reference-topology perimeter test this
does not replace).
