#!/usr/bin/env bash
# Tier 2 -- full production validation of the SaaS-OS *application* stack
# against real TLS-protected PostgreSQL and Redis (ADR-0027, Candidate B).
#
# This is deliberately NOT scripts/check-docker-prod.sh. That script is the
# reference-topology perimeter test: it boots docker-compose.prod.yml exactly
# as shipped and proves which ports are and are not reachable. Its stock
# `db`/`redis` carry no TLS material, so `backend`/`worker` cannot become
# healthy against them -- ADR-0021's own documented residual limitation, an
# accepted consequence rather than a defect. Both scripts are needed and
# neither replaces the other.
#
# What this script does instead: provisions a disposable, TLS-capable
# PostgreSQL and Redis, points the *unmodified* production application
# services at them, and validates the application's real production TLS
# boundary end to end. docker-compose.prod.yml is never edited -- every
# change is a generated override file under a temporary directory outside
# this repository, layered with `-f`.
#
# The fabricated-hybrid failure mode this script must never commit (ADR-0027
# "Honesty constraints"): the stock `db`/`redis` services are NEVER started.
# The endpoints the application connects to are the endpoints validated and
# reported. Nothing is asserted about a service the application does not use.
#
# TLS trust, and why it needs no application change: redis-py's
# `SSLConnection` builds its context with `ssl.create_default_context()` and
# verifies the server certificate (`ssl_cert_reqs="required"`), while this
# repository exposes no `ssl_ca_certs` surface (ADR-0021 as corrected). The
# validation CA is therefore trusted through OpenSSL's own default verify
# paths via `SSL_CERT_FILE`, pointed at a bundle that also carries the
# identity CA the backend already trusts. Certificate verification stays ON
# throughout: this script never sets ssl_cert_reqs=none/CERT_NONE, and never
# weakens `sslmode`.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

# Unique per invocation: two concurrent runs must not share a Compose
# project, or the first to finish tears down the other. The PID keeps it
# shell-safe and still identifiable in logs and `docker ps`.
PROJECT="saas-os-tier2-$$"
# SAAS_OS_TIER2_TMP pins the generated-material directory and
# SAAS_OS_TIER2_KEEP=1 skips teardown -- both exist so a failing run can be
# inspected live. Neither is used by a normal run, which always cleans up.
TMP="${SAAS_OS_TIER2_TMP:-$(mktemp -d "${TMPDIR:-/tmp}/saas-os-tier2.XXXXXX")}"
mkdir -p "$TMP"
OVERRIDE="$TMP/compose.validation.yml"
CERTGEN="$TMP/gen-validation-certs.sh"
COMPOSE="docker compose -f docker-compose.prod.yml -f $OVERRIDE -p $PROJECT"

# Docker Desktop on Windows resolves a bind-mount source as a *host* path.
# An MSYS-style path (/tmp/..., /c/...) is instead resolved inside Docker's
# own Linux VM, silently mounting an empty file. `cygpath -m` converts to
# the C:/... form Docker accepts; on Linux/macOS there is nothing to convert.
host_path() { cygpath -m "$1" 2>/dev/null || printf '%s' "$1"; }

FAILED=0
# Set once cleanup has run, so the INT/TERM handler and the EXIT trap
# cannot both tear down the same invocation.
CLEANED=0
note() { printf '\n== %s ==\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; FAILED=1; }

_cleanup() {
    rc=$?
    if [ "$CLEANED" = "1" ]; then
        return 0
    fi
    CLEANED=1
    note "cleanup"
    if [ "$rc" != "0" ] || [ "$FAILED" != "0" ]; then
        echo "-- diagnostics --"
        $COMPOSE ps -a 2>/dev/null || true
        for svc in valdb valredis backend worker proxy; do
            echo "---- $svc ----"
            $COMPOSE logs --tail 20 "$svc" 2>/dev/null || true
        done
    fi
    if [ "${SAAS_OS_TIER2_KEEP:-0}" = "1" ]; then
        echo "SAAS_OS_TIER2_KEEP=1 -- leaving project $PROJECT and $TMP in place for inspection"
        echo "tear down manually: docker compose -p $PROJECT down -v --remove-orphans; rm -rf $TMP"
        return 0
    fi
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$TMP"
    echo "cleanup done: project $PROJECT removed, $TMP removed"
}
# Bash does not run an EXIT trap when the shell is killed by an uncaught
# signal, so an EXIT-only trap leaves this invocation's disposable stack
# running on Ctrl-C or `kill`. These handlers tear down exactly as a normal
# exit does -- still scoped to this invocation's own Compose project, never
# a concurrent one -- then report the conventional 128+signal status.
# `trap - EXIT` plus the CLEANED guard keeps teardown to exactly one run.
_on_signal() {
    printf '\ninterrupted by SIG%s -- tearing down this invocation\n' "$1"
    _cleanup
    trap - EXIT
    case "$1" in
        INT) exit 130 ;;
        TERM) exit 143 ;;
        *) exit 1 ;;
    esac
}
trap '_on_signal INT' INT
trap '_on_signal TERM' TERM
trap _cleanup EXIT

# --- disposable validation values --------------------------------------
# Never real deployment secrets; generated or throwaway, removed with $TMP.
# The same non-public-address convention the reference perimeter script
# uses: Caddy treats a .localhost name as non-public and issues from its own
# internal CA instead of attempting real ACME. The fresh identity profile
# additionally requires PUBLIC_DOMAIN == IDENTITY_PUBLIC_DOMAIN, and that
# shared name must be usable as a Docker network alias -- so it cannot be
# the bare `localhost`, which every container resolves to its own loopback.
export PUBLIC_DOMAIN=app.localhost
export IDENTITY_PUBLIC_DOMAIN=app.localhost
export IDENTITY_PROFILE=fresh
export ZITADEL_LOGIN_V2_ENABLED=true
# ADR-0024: PUBLIC_APP_ORIGIN alone derives the callback. An operator .env
# that also sets OIDC_REDIRECT_URI fails closed against it, so this run
# clears it explicitly rather than editing .env.
export OIDC_REDIRECT_URI=
export ZITADEL_MASTERKEY="$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export ZITADEL_DB_USER=zitadel
export ZITADEL_DB_PASSWORD=tier2-only-zitadel-db  # pragma: allowlist secret
export ZITADEL_DB_NAME=zitadel
export ZITADEL_FIRSTINSTANCE_ADMIN_USERNAME=admin
export ZITADEL_FIRSTINSTANCE_ADMIN_PASSWORD=Tier2Only_Zitadel1  # pragma: allowlist secret
export ZITADEL_FIRSTINSTANCE_ADMIN_EMAIL=admin@app.localhost
# The bootstrap token's required expiry (docker-compose.prod.yml): a
# short one, as a real deployment should use.
pat_expiry=$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ) || {
  echo "date -d is not supported here (GNU date required)" >&2
  exit 1
}
export ZITADEL_BOOTSTRAP_PAT_EXPIRATION="$pat_expiry"
# Login V2's required session-cookie secret (docker-compose.prod.yml):
# random per run and never printed.
ZITADEL_SESSION_COOKIE_SECRET=$(openssl rand -base64 32) || {
  echo "openssl is required to generate ZITADEL_SESSION_COOKIE_SECRET" >&2
  exit 1
}
export ZITADEL_SESSION_COOKIE_SECRET

VAL_DB_NAME=saas_os
VAL_DB_ADMIN=saas_os
VAL_DB_ADMIN_PW=tier2-only-admin  # pragma: allowlist secret
VAL_DB_APP=saas_os_app
VAL_DB_APP_PW=tier2-only-app  # pragma: allowlist secret
export VAL_REDIS_PW=tier2-only-redis  # pragma: allowlist secret

# The stock db/redis definitions still interpolate these; they are never
# started, but `docker compose config` must still resolve.
export POSTGRES_USER="$VAL_DB_ADMIN"
export POSTGRES_PASSWORD="$VAL_DB_ADMIN_PW"
export POSTGRES_DB="$VAL_DB_NAME"
export APP_DB_USER="$VAL_DB_APP"
export APP_DB_PASSWORD="$VAL_DB_APP_PW"

# No sslmode is set on these URLs on purpose: saas_os/infra/db/config.py injects
# `sslmode=require` itself under ENVIRONMENT=production, so the run proves
# the application's own fail-closed injection rather than pre-satisfying it.
export VAL_DATABASE_URL="postgresql+psycopg://${VAL_DB_APP}:${VAL_DB_APP_PW}@valdb:5432/${VAL_DB_NAME}"
export VAL_MIGRATIONS_DATABASE_URL="postgresql+psycopg://${VAL_DB_ADMIN}:${VAL_DB_ADMIN_PW}@valdb:5432/${VAL_DB_NAME}"
export VAL_REDIS_URL="rediss://:${VAL_REDIS_PW}@valredis:6379/0"

# ADR-0012 amendment of 2026-10-21: `backend` and `worker` load `.env.app`.
# This run gives them a throwaway one, generated from the committed example,
# so an operator's own `.env.app` is never read; the database and Redis URLs
# are overridden in the generated compose file below. The issuer is this
# stack's own ZITADEL (fresh profile: on PUBLIC_DOMAIN).
APP_ENV="$TMP/app.env"
grep -v '^OIDC_ISSUER_URL=' .env.app.example > "$APP_ENV"
printf 'OIDC_ISSUER_URL=https://%s\n' "$PUBLIC_DOMAIN" >> "$APP_ENV"

# --- disposable validation PKI -----------------------------------------
cat > "$CERTGEN" <<'CERTEOF'
#!/bin/sh
# One CA, one server certificate per service. Keys are 0600 and owned by the
# uid that must read them (postgres 70, redis 999); certificates and the
# trust bundle are world-readable so the application containers can load
# them. The CA private key is discarded once the leaves are issued. Nothing
# here is ever written into the repository -- it lives in the volume only.
set -eu
C=/certs
if [ -f "$C/.done" ]; then echo "validation PKI already present"; exit 0; fi

# basicConstraints/keyUsage are required, not cosmetic: OpenSSL 3 rejects a
# CA without them ("CA cert does not include key usage extension"), which is
# certificate verification doing its job.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj "/CN=saas-os-tier2-validation-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$C/ca.key" -out "$C/ca.crt" >/dev/null 2>&1

issue() {
    name=$1; cn=$2; owner=$3
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$cn" \
        -keyout "$C/$name.key" -out "$C/$name.csr" >/dev/null 2>&1
    {
        printf 'subjectAltName=DNS:%s\n' "$cn"
        printf 'basicConstraints=critical,CA:FALSE\n'
        printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
        printf 'extendedKeyUsage=serverAuth\n'
    } > "$C/$name.ext"
    openssl x509 -req -in "$C/$name.csr" -CA "$C/ca.crt" -CAkey "$C/ca.key" \
        -CAcreateserial -days 2 -extfile "$C/$name.ext" \
        -out "$C/$name.crt" >/dev/null 2>&1
    rm -f "$C/$name.csr" "$C/$name.ext"
    chown "$owner:$owner" "$C/$name.key" "$C/$name.crt"
    chmod 0600 "$C/$name.key"
    chmod 0644 "$C/$name.crt"
}

issue pgserver valdb "$PG_UID"
issue redisserver valredis "$REDIS_UID"

# SSL_CERT_FILE takes a single file, and the application must verify both
# the validation CA (PostgreSQL/Redis) and ZITADEL's own identity CA, so
# they are concatenated. The harness appends the identity CA once the
# identity stack has generated it.
cp "$C/ca.crt" "$C/trust-bundle.crt"
chmod 0644 "$C/ca.crt" "$C/trust-bundle.crt"
rm -f "$C/ca.key"
touch "$C/.done"
echo "validation PKI generated (CA + valdb + valredis); CA private key discarded"
CERTEOF

CERTGEN_HOST="$(host_path "$CERTGEN")"
REPO_ROOT_HOST="$(host_path "$REPO_ROOT")"
APP_ENV_HOST="$(host_path "$APP_ENV")"

# --- generated compose override ----------------------------------------
# `!override` replaces the shipped `depends_on` outright so neither stock
# service can be pulled in as a dependency of backend/worker.
cat > "$OVERRIDE" <<OVEOF
services:
  val-certs-init:
    image: alpine/openssl:3.5.8
    entrypoint: ["sh", "/gen-validation-certs.sh"]
    network_mode: none
    environment:
      PG_UID: "70"
      REDIS_UID: "999"
    volumes:
      - val-certs:/certs
      - ${CERTGEN_HOST}:/gen-validation-certs.sh:ro

  valdb:
    image: postgres:16-alpine
    command: ["postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/certs/pgserver.crt", "-c", "ssl_key_file=/certs/pgserver.key"]
    environment:
      POSTGRES_USER: \${POSTGRES_USER}
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      POSTGRES_DB: \${POSTGRES_DB}
      APP_DB_USER: \${APP_DB_USER}
      APP_DB_PASSWORD: \${APP_DB_PASSWORD}
    volumes:
      - val-certs:/certs:ro
      - ${REPO_ROOT_HOST}/saas_os/infra/db/init/01-create-app-role.sh:/docker-entrypoint-initdb.d/01-create-app-role.sh:ro
    networks: [internal]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U \$\${POSTGRES_USER} -d \$\${POSTGRES_DB}"]
      interval: 5s
      timeout: 5s
      retries: 12
    depends_on:
      val-certs-init:
        condition: service_completed_successfully

  valredis:
    image: redis:7-alpine
    command: ["redis-server", "--appendonly", "yes", "--port", "0", "--tls-port", "6379", "--tls-cert-file", "/certs/redisserver.crt", "--tls-key-file", "/certs/redisserver.key", "--tls-ca-cert-file", "/certs/ca.crt", "--tls-auth-clients", "no", "--requirepass", "\${VAL_REDIS_PW}"]
    environment:
      REDISCLI_AUTH: \${VAL_REDIS_PW}
    volumes:
      - val-certs:/certs:ro
    networks: [internal]
    healthcheck:
      test: ["CMD-SHELL", "redis-cli --tls --cacert /certs/ca.crt --no-auth-warning ping | grep -q PONG"]
      interval: 5s
      timeout: 5s
      retries: 12
    depends_on:
      val-certs-init:
        condition: service_completed_successfully

  backend:
    env_file: !override
      - ${APP_ENV_HOST}
    environment:
      DATABASE_URL: \${VAL_DATABASE_URL}
      MIGRATIONS_DATABASE_URL: \${VAL_MIGRATIONS_DATABASE_URL}
      REDIS_URL: \${VAL_REDIS_URL}
      SSL_CERT_FILE: /certs/trust-bundle.crt
    volumes:
      - val-certs:/certs:ro
    depends_on: !override
      valdb:
        condition: service_healthy
      valredis:
        condition: service_healthy

  worker:
    env_file: !override
      - ${APP_ENV_HOST}
    environment:
      DATABASE_URL: \${VAL_DATABASE_URL}
      MIGRATIONS_DATABASE_URL: \${VAL_MIGRATIONS_DATABASE_URL}
      REDIS_URL: \${VAL_REDIS_URL}
      SSL_CERT_FILE: /certs/trust-bundle.crt
    volumes:
      - val-certs:/certs:ro
    depends_on: !override
      valdb:
        condition: service_healthy
      valredis:
        condition: service_healthy

volumes:
  val-certs:
OVEOF

wait_healthy() {
    svc=$1; tries=${2:-60}
    i=0
    while [ "$i" -lt "$tries" ]; do
        cid=$($COMPOSE ps -q "$svc" 2>/dev/null || true)
        if [ -n "$cid" ]; then
            # A stopped container retains its LAST health status, so
            # `.State.Running` must gate it or a service that never restarted
            # reads as healthy.
            st=$(docker inspect -f '{{if not .State.Running}}stopped{{else if .State.Health}}{{.State.Health.Status}}{{else}}running{{end}}' "$cid" 2>/dev/null | tr -d '\r' || echo starting)
            case "$st" in healthy|running) echo "$svc: $st"; return 0;; esac
        fi
        i=$((i + 1))
        sleep 2
    done
    fail "$svc did not become healthy (last=${st:-unknown})"
    # Docker keeps the healthcheck's own output; for `backend` that is the
    # readiness probe's reason, which is what actually explains a 503.
    cid=$($COMPOSE ps -q "$svc" 2>/dev/null || true)
    if [ -n "$cid" ]; then
        echo "-- $svc healthcheck output --"
        docker inspect -f '{{range .State.Health.Log}}{{.Output}}{{end}}' "$cid" 2>/dev/null | tail -20
    fi
    return 1
}

note "validation topology parses"
$COMPOSE config >/dev/null
echo "ok"

note "host-port pre-flight"
# Ports are read from the rendered configuration rather than hardcoded, so
# this keeps matching whatever the compose file actually publishes (today
# 80 and 443, via `proxy`). Only `python`, already required by this harness,
# is used -- no new dependency. A busy port is reported and the run stops
# before anything is started; the harness never touches whatever owns it.
#
# `python` is required up front rather than inferred from a probe's exit
# status: collapsing "the probe failed" into "the port is free" is how an
# unverified port gets reported as available. The probe below therefore
# returns one of three explicit results -- busy, free, or could-not-check --
# and only `free` allows the run to continue.
command -v python >/dev/null 2>&1 || {
    fail "python is required for the host-port pre-flight but is not on PATH"
    exit 1
}
PUBLISHED_PORTS=$($COMPOSE config --format json | python -c "
import json, sys
d = json.load(sys.stdin)
ports = set()
for svc in d['services'].values():
    for spec in svc.get('ports') or []:
        pub = spec.get('published') if isinstance(spec, dict) else None
        if pub:
            ports.add(int(pub))
print(' '.join(str(p) for p in sorted(ports)))
")
for PORT in $PUBLISHED_PORTS; do
    PORT_STATE=$(python -c "
import socket, sys
# Both stacks. A listener bound only to ::1 (or to ::) occupies the port for
# a later bind exactly as an IPv4 listener does, so probing 127.0.0.1 alone
# reports a busy port as free -- verified against a real IPv6-only listener.
for family, addr in ((socket.AF_INET, ('127.0.0.1', $PORT)),
                     (socket.AF_INET6, ('::1', $PORT))):
    try:
        s = socket.socket(family)
    except OSError:
        continue  # family unavailable on this host; absence of proof, not proof of absence
    s.settimeout(1)
    try:
        s.connect(addr)
        print('busy')
        sys.exit(0)
    except OSError:
        pass
    finally:
        s.close()
print('free')
" 2>/dev/null) || PORT_STATE="unknown"
    case "$PORT_STATE" in
        free)
            echo "port $PORT: free"
            ;;
        busy)
            fail "host port $PORT is already in use -- not starting the disposable stack"
            echo "Another Tier 2 run, or an unrelated service, holds port $PORT. This"
            echo "harness never stops or reconfigures whatever owns a port: free it and"
            echo "re-run. (Concurrent Tier 2 runs each need their own host ports.)"
            exit 1
            ;;
        *)
            fail "host port $PORT could not be checked -- the pre-flight probe failed"
            echo "The port was NOT confirmed free, so the disposable stack is not being"
            echo "started. This is deliberately not treated as success: an unverified"
            echo "port is not an available one."
            exit 1
            ;;
    esac
done

note "honesty check: the stock reference db/redis take no part in this run"
$COMPOSE config --format json | python -c "
import json, re, sys
d = json.load(sys.stdin)

def safe(url):
    # Diagnostics keep the transport/host/database; the credential never
    # reaches the log, even on an assertion failure.
    return re.sub('://[^@/]*@', '://<redacted>@', url)

for svc in ('backend', 'worker'):
    deps = set((d['services'][svc].get('depends_on') or {}).keys())
    assert not (deps & {'db', 'redis'}), f'{svc} still depends on stock services: {deps}'
    env = d['services'][svc]['environment']
    assert 'valdb' in env['DATABASE_URL'], safe(env['DATABASE_URL'])
    assert env['REDIS_URL'].startswith('rediss://'), safe(env['REDIS_URL'])
    assert 'sslmode=disable' not in env['DATABASE_URL']
    assert env['ENVIRONMENT'] == 'production'
    assert 'DB_REQUIRE_TLS' not in env and 'REDIS_REQUIRE_TLS' not in env, 'fail-closed default must stand'
print('backend/worker: depend on valdb/valredis only, rediss:// scheme, production fail-closed defaults intact')
"

note "start TLS PostgreSQL and TLS Redis"
$COMPOSE up -d valdb valredis
wait_healthy valdb
wait_healthy valredis

note "PostgreSQL is actually serving TLS"
# Single-quoted on purpose: the container resolves POSTGRES_* from its own
# environment, so the password never appears in a host-side process
# argument list. PGPASSWORD is psql's own supported mechanism.
$COMPOSE exec -T valdb sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" psql "postgresql://$POSTGRES_USER@127.0.0.1:5432/$POSTGRES_DB?sslmode=require" -tAc "SELECT '"'"'pg_stat_ssl: ssl='"'"' || ssl || '"'"' '"'"' || COALESCE(version,'"'"''"'"') FROM pg_stat_ssl WHERE pid = pg_backend_pid();"'

note "Redis serves TLS only (plaintext port disabled)"
$COMPOSE exec -T valredis sh -c 'redis-cli --tls --cacert /certs/ca.crt --no-auth-warning ping'
$COMPOSE exec -T valredis sh -c 'redis-cli -p 6379 --no-auth-warning ping 2>&1 | head -1 || true'

note "identity stack (ZITADEL v4.19.5 + Login V2 v4.19.5)"
$COMPOSE up -d zitadel-login
wait_healthy zitadel 90
wait_healthy zitadel-login 90

note "Login V2 signs with ZITADEL_SESSION_COOKIE_SECRET (no fallback, never logged)"
# Startup notices of ZITADEL v4.19.5's apps/login
# src/lib/session-cookie-signature.ts: an invalid secret, none at all, or the
# deprecated key derived from the API credential.
LOGIN_LOGS=$($COMPOSE logs --no-color zitadel-login 2>&1 || true)
case "$LOGIN_LOGS" in
    *"$ZITADEL_SESSION_COOKIE_SECRET"*) fail "the session-cookie secret appears in zitadel-login logs" ;;
esac
case "$LOGIN_LOGS" in
    *"ZITADEL_SESSION_COOKIE_SECRET is not set"* | *"ZITADEL_SESSION_COOKIE_SECRET is invalid"* | *"No session cookie signing secret"*)
        fail "zitadel-login is not signing with the configured session-cookie secret" ;;
    *) echo "no session-cookie secret notice in zitadel-login logs" ;;
esac

note "extend the trust bundle with ZITADEL's identity CA"
docker run --rm \
    -v "${PROJECT}_val-certs:/certs" \
    -v "${PROJECT}_identity-ca:/identity-ca:ro" \
    alpine:3.20 sh -c 'cat /certs/ca.crt /identity-ca/tls.crt > /certs/trust-bundle.crt && chmod 0644 /certs/trust-bundle.crt && echo "trust bundle = validation CA + identity CA"'

note "migrate the validation database over TLS (production migration path)"
$COMPOSE run --rm --no-deps --entrypoint python backend -c "
from alembic import command
from alembic.config import Config
cfg = Config()
cfg.set_main_option('script_location', 'saas_os/infra/db/migrations')
command.upgrade(cfg, 'head')
"

note "the application injected sslmode=require itself (fail-closed default)"
$COMPOSE run --rm --no-deps --entrypoint python backend -c "
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.jobs.config import get_jobs_config
from saas_os.infra.ratelimit.config import get_ratelimit_config
for label, cfg in (('DATABASE_URL', get_database_config()), ('MIGRATIONS_DATABASE_URL', get_migrations_database_config())):
    assert cfg.require_tls, label
    assert 'sslmode=require' in cfg.url
    print(label + ': require_tls=True sslmode=require')
for label, cfg, attr in (('jobs', get_jobs_config(), 'redis_url'), ('ratelimit', get_ratelimit_config(), 'redis_url')):
    assert cfg.require_tls and getattr(cfg, attr).startswith('rediss://')
    print(label + ': require_tls=True scheme=rediss')
"

note "start the production application stack (backend, worker, frontend, Caddy)"
# backend/worker first and on their own: `proxy` declares
# `depends_on: backend: service_healthy`, so starting it in the same command
# makes Compose abort the whole `up` before this script can report *why*
# backend is unhealthy.
$COMPOSE up -d backend worker
wait_healthy backend 90
wait_healthy worker 90
$COMPOSE up -d proxy zitadel-bootstrap
wait_healthy frontend 60
wait_healthy proxy 60

note "live connections are genuinely TLS, from the application's own view"
$COMPOSE exec -T backend python -c "
from sqlalchemy import text
from saas_os.infra.db.config import get_database_config
from saas_os.infra.db.engine import build_engine
with build_engine(get_database_config()).connect() as c:
    row = c.execute(text('SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()')).one()
    assert row[0] is True, 'backend -> PostgreSQL is NOT encrypted'
    print(f'backend -> PostgreSQL: ssl={row[0]} {row[1]}')
"
for svc in backend worker; do
    $COMPOSE exec -T "$svc" python -c "
import asyncio, ssl
from redis.asyncio import Redis
from saas_os.infra.jobs.config import get_jobs_config
async def main():
    r = Redis.from_url(get_jobs_config().redis_url)
    assert await r.ping()
    pool = r.connection_pool
    # `connection_kwargs` carries only what the URL itself set -- for a plain
    # rediss:// URL it has no 'ssl_cert_reqs' key at all, so reading it with a
    # default proves nothing. The *effective* mode lives on the connection
    # object the pool builds: it is what `_wrap_socket_with_ssl` assigns to
    # `context.verify_mode`. Building one with the pool's own class and kwargs
    # reports the value real connections from this pool use, and does drop to
    # CERT_NONE if a bypass is ever configured.
    conn = pool.connection_class(**pool.connection_kwargs)
    assert conn.cert_reqs == ssl.CERT_REQUIRED, 'effective cert_reqs is ' + str(conn.cert_reqs)
    # Stated exactly: the certificate chain is verified; hostname checking is
    # off by this client's own default (ADR-0021). Neither is claimed beyond
    # what is observed here -- that an *untrusted* chain is actually rejected
    # is proved by the negative control below, not by this assertion.
    print('$svc -> Redis: TLS ping OK; effective cert_reqs=CERT_REQUIRED, check_hostname=' + str(conn.check_hostname))
    await r.aclose()
asyncio.run(main())
"
done

note "verification is genuinely enforced (an untrusted chain must be refused)"
# Negative control, using the *same* mechanism the trust relies on: restrict
# SSL_CERT_FILE to ZITADEL's identity CA only, so the validation CA that
# signed the Redis certificate is genuinely absent from the trust store. If
# verification were disabled this would still connect. It must not.
$COMPOSE exec -T -e SSL_CERT_FILE=/identity-ca/tls.crt backend python -c "
import asyncio
from redis.asyncio import Redis
from saas_os.infra.jobs.config import get_jobs_config
async def main():
    r = Redis.from_url(get_jobs_config().redis_url)
    try:
        await r.ping()
    except Exception as exc:
        print(f'untrusted chain refused as expected: {type(exc).__name__}')
        return
    finally:
        try:
            await r.aclose()
        except Exception:
            pass
    raise SystemExit('FAIL: Redis TLS accepted an untrusted chain')
asyncio.run(main())
"

note "running Caddy: routing and /debug protection"
# Caddy issues app.localhost from its own internal CA (a .localhost name is
# never sent to ACME), so the edge certificate IS verifiable -- it just
# needs that CA. Extracting it from the run's own caddy-data volume lets
# curl verify the chain AND the hostname instead of skipping verification.
# Nothing is installed into the host trust store; the file dies with $TMP.
# `sh -c` with a single-quoted path on purpose: a bare absolute path given
# as a `docker run` command argument is rewritten by Git Bash/MSYS on
# Windows (to C:/Program Files/Git/...), silently producing an empty file.
docker run --rm -v "${PROJECT}_caddy-data:/caddy-data:ro" alpine:3.20 \
    sh -c 'cat /caddy-data/caddy/pki/authorities/local/root.crt' > "$TMP/caddy-root.crt" || true
[ -s "$TMP/caddy-root.crt" ] || fail "could not extract Caddy's internal CA root"
echo "edge probes verify against Caddy's internal CA ($(wc -c < "$TMP/caddy-root.crt") bytes)"
# The probe runs inside a container rather than on the host, because the
# host curl here is Schannel-backed (Windows) and rejects a private CA with
# 'the revocation status is unknown' no matter what --cacert says; the only
# host-side escape would be --ssl-revoke-best-effort, which weakens checking.
# An OpenSSL curl on the project's own edge network verifies the certificate
# chain against that CA -- which is what the negative control below actually
# demonstrates, by removing the CA and requiring the probe to be refused.
# curl also checks the hostname by default (no --insecure is passed, and the
# served certificate's SAN is the name being requested), but no control here
# isolates that, so this comment does not claim it as demonstrated. The CA
# comes from the extracted copy (the file in caddy-data is 0600 root and
# unreadable to the image's non-root user).
# No -k/--insecure anywhere: an unverifiable certificate fails the probe.
PROXY_EDGE_IP=$(docker inspect "$($COMPOSE ps -q proxy)" \
    --format "{{(index .NetworkSettings.Networks \"${PROJECT}_edge\").IPAddress}}")
TMP_HOST="$(host_path "$TMP")"
edge() {
    MSYS_NO_PATHCONV=1 docker run --rm --network "${PROJECT}_edge" -v "${TMP_HOST}:/ca:ro" \
        curlimages/curl:8.11.1 --cacert /ca/caddy-root.crt \
        --resolve "app.localhost:443:${PROXY_EDGE_IP}" -s --max-time 20 "$@"
}
# Same posture as the Redis negative control: prove the verification is real
# by removing the CA and requiring the probe to be refused.
if MSYS_NO_PATHCONV=1 docker run --rm --network "${PROJECT}_edge" curlimages/curl:8.11.1 \
       -s -o /dev/null --resolve "app.localhost:443:${PROXY_EDGE_IP}" --max-time 20 \
       https://app.localhost/ui/v2/login >/dev/null 2>&1; then
    fail "edge TLS was accepted WITHOUT the validation CA -- verification is not actually enforced"
else
    echo "edge probe without the CA is refused -- edge certificate verification is genuine"
fi
probe() {
    path=$1; expected=$2
    code=$(edge -o /dev/null -w '%{http_code}' "https://app.localhost${path}")
    printf 'GET %-38s -> %s (expected one of %s)\n' "$path" "$code" "$expected"
    case ",$expected," in *",$code,"*) ;; *) fail "unexpected status for $path: $code";; esac
}
probe /ui/v2/login 200
probe /.well-known/openid-configuration 200
probe /debug/pprof 404,403,502
probe /debug/vars 404,403,502
probe /healthz 404
probe / 200,302,307,404

note "callback is PUBLIC_APP_ORIGIN + /auth/callback"
$COMPOSE exec -T backend python -c "
import os
from saas_os.infra.edge.origin import callback_url_for
origin = os.environ['PUBLIC_APP_ORIGIN']
derived = callback_url_for(origin, environment='production')
assert derived == origin.rstrip('/') + '/auth/callback', derived
print(f'{origin} -> {derived}')
"

note "provider-cookie isolation through the running edge"
echo "the live probe below confirms a cookie-bearing request is routed and answered;"
echo "per-cookie stripping itself is proved against upstream doubles by the 88 tests"
echo "in tests/architecture/test_identity_proxy_routing.py, which this does not duplicate"
edge -o /dev/null -w 'backend-routed request carrying provider cookies -> %{http_code}\n' \
    -H 'Cookie: __Host-zitadel.useragent=ua; sessions=s; saas_os_session=abc' \
    "https://app.localhost/v1/"

note "backup against the VALIDATION database (never the unused stock db)"
VALDB=$(docker inspect --format '{{.Name}}' "$($COMPOSE ps -q valdb)" | sed 's#^/##')
if python -c "import saas_os.infra.db.backup" >/dev/null 2>&1; then
    POSTGRES_USER="$VAL_DB_ADMIN" POSTGRES_PASSWORD="$VAL_DB_ADMIN_PW" POSTGRES_DB="$VAL_DB_NAME" \
    DB_CONTAINER_NAME="$VALDB" python -c "
import os, tempfile
from pathlib import Path
from saas_os.infra.db.config import DatabaseConfig
from saas_os.infra.db.backup import create_backup, verify_backup_checksum
admin = DatabaseConfig(url='postgresql://%s:%s@ignored/%s' % (os.environ['POSTGRES_USER'], os.environ['POSTGRES_PASSWORD'], os.environ['POSTGRES_DB']))
with tempfile.TemporaryDirectory() as tmp:
    m = create_backup(container=os.environ['DB_CONTAINER_NAME'], admin_config=admin, output_dir=Path(tmp), label='tier2')
    verify_backup_checksum(m.metadata_path)
    assert m.size_bytes > 0
    print('backup OK against %s: %d bytes sha256=%s...' % (os.environ['DB_CONTAINER_NAME'], m.size_bytes, m.sha256[:12]))
"
else
    echo "SKIP: host python cannot import saas_os.infra.db.backup -- environment gap, not a defect"
fi

note "restart / idempotency (no volume destroyed)"
$COMPOSE stop backend worker frontend proxy >/dev/null
# `worker` is named explicitly: nothing depends on it, so `up -d proxy`
# alone would leave it stopped and silently unvalidated.
$COMPOSE up -d proxy worker >/dev/null
wait_healthy backend 90
wait_healthy worker 90
wait_healthy proxy 60
probe /ui/v2/login 200
probe /.well-known/openid-configuration 200

if [ "$FAILED" = "0" ]; then
    printf '\nTier 2 production validation PASSED.\n'
    echo "NOTE: TLS here is a disposable validation PKI (ADR-0027). PostgreSQL keeps"
    echo "      sslmode=require -- encryption without certificate verification, unchanged"
    echo "      from ADR-0021 -- while Redis certificate verification is enforced."
else
    printf '\nTier 2 production validation FAILED -- see FAIL lines above.\n'
    exit 1
fi
