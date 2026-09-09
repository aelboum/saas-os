#!/usr/bin/env bash
# P2.3 -- production network perimeter + TLS validation. Separate from
# scripts/check-docker.sh (which validates the *development* topology,
# docker-compose.yml, unchanged by this phase): this script builds and
# runs docker-compose.prod.yml in an isolated Compose project, then
# proves the perimeter itself -- which ports are (and are not) reachable
# from outside the stack, that PostgreSQL/Redis/backend/frontend are
# unreachable directly, that TLS terminates at the proxy, that the P2.2
# authentication flow and P2.1 worker both still function behind it, and
# that a spoofed X-Forwarded-For cannot bypass the pre-login rate limit.
#
# PUBLIC_DOMAIN=localhost for this run only (never a real deployment
# value) -- Caddy recognizes "localhost" as a non-public address and
# automatically issues a certificate from its own internal CA instead of
# attempting real ACME. This deterministically proves TLS termination,
# the HTTP->HTTPS redirect, and certificate validity *for Caddy's own
# trust chain*; it is explicitly NOT a live ACME/DNS validation, and this
# script never claims it is (docs/DEPLOYMENT-ARCHITECTURE.md §11).
set -euo pipefail
cd "$(dirname "$0")/.."

# The real (Linux VPS) deployment target has `python3`; this validation
# also runs on developer machines that may only have `python` on PATH.
PY="$(command -v python3 || command -v python)"

# P2.4's backup-mechanism check below needs this repository's own
# dependencies importable (infra/db/backup's docker-exec transport is
# designed to run from the deployment host's own venv, not from inside a
# container -- see deploy/saas-os-backup.service) -- prefer a local
# `.venv` over the bare system interpreter above when one exists and
# actually has this repository installed.
for CANDIDATE in .venv/bin/python .venv/Scripts/python.exe; do
    if [ -x "$CANDIDATE" ] && "$CANDIDATE" -c "import infra.db.backup" >/dev/null 2>&1; then
        PY="$CANDIDATE"
        break
    fi
done

[ -f .env ] || cp .env.example .env

# Baseline reachability, captured BEFORE this compose project starts
# anything. A known, pre-existing artifact on some development machines
# (documented throughout this repository's own session history): a
# native, unrelated PostgreSQL service can already occupy host port 5432
# for reasons that have nothing to do with this project. A blind
# post-startup "is 5432 reachable" check would then fail even though
# `docker-compose.prod.yml` itself publishes nothing -- the correct,
# unambiguous proof (also performed below, via `docker port` and the
# rendered compose config) is that *this compose project* publishes no
# such port; the reachability comparison here additionally proves this
# project does not make anything newly reachable that wasn't already.
BASELINE_PORT_STATE=$("$PY" -c "
import socket
for port in (5432, 6379, 8000, 3000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect(('127.0.0.1', port))
        print(f'{port}:reachable')
    except OSError:
        print(f'{port}:unreachable')
    finally:
        s.close()
")
echo "-- baseline host port reachability (before this compose project starts) --"
echo "$BASELINE_PORT_STATE"

COMPOSE_PROD="docker compose -f docker-compose.prod.yml -p saas-os-check-prod"
_cleanup() {
    $COMPOSE_PROD down -v --remove-orphans >/dev/null 2>&1 || true
}
trap _cleanup EXIT

echo "== docker compose config (production topology parses cleanly) =="
PUBLIC_DOMAIN=localhost $COMPOSE_PROD config >/dev/null

echo "== build: backend, worker (same Dockerfile), frontend =="
$COMPOSE_PROD build backend worker frontend

echo "== start: db, redis (internal only) =="
$COMPOSE_PROD up -d db redis

echo "-- waiting for db healthy --"
DB_CID=$($COMPOSE_PROD ps -q db)
for _ in $(seq 1 30); do
    STATUS=$(docker inspect -f '{{.State.Health.Status}}' "$DB_CID" 2>/dev/null || echo "")
    [ "$STATUS" = "healthy" ] && break
    sleep 2
done
[ "$STATUS" = "healthy" ] || { echo "FAIL: db never became healthy"; $COMPOSE_PROD logs db; exit 1; }

echo "== P2.4: PostgreSQL data volume is a named, persistent Docker volume (not the container's own writable layer) =="
DB_MOUNT=$(docker inspect "$DB_CID" --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}} {{.Name}}{{end}}{{end}}')
echo "db /var/lib/postgresql/data mount: $DB_MOUNT"
case "$DB_MOUNT" in
    "volume "*) : ;;
    *) echo "FAIL: PostgreSQL data is not on a named Docker volume: $DB_MOUNT"; exit 1 ;;
esac

echo "== P2.4: Redis persistence (AOF) enabled, on a named, persistent Docker volume =="
REDIS_CID=$($COMPOSE_PROD ps -q redis)
REDIS_MOUNT=$(docker inspect "$REDIS_CID" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}} {{.Name}}{{end}}{{end}}')
echo "redis /data mount: $REDIS_MOUNT"
case "$REDIS_MOUNT" in
    "volume "*) : ;;
    *) echo "FAIL: Redis data is not on a named Docker volume: $REDIS_MOUNT"; exit 1 ;;
esac
AOF_SETTING=$(docker exec "$REDIS_CID" redis-cli CONFIG GET appendonly | tail -n 1)
[ "$AOF_SETTING" = "yes" ] || { echo "FAIL: Redis appendonly is not enabled (got: $AOF_SETTING)"; exit 1; }
echo "redis appendonly: $AOF_SETTING"

echo "== migrate the disposable database to head (through the migration/admin role, from a throwaway container on the same network) =="
$COMPOSE_PROD run --rm --no-deps --entrypoint python backend -c "
from alembic import command
from alembic.config import Config
cfg = Config()
cfg.set_main_option('script_location', 'infra/db/migrations')
command.upgrade(cfg, 'head')
"

echo "== start: backend, worker =="
$COMPOSE_PROD up -d backend worker
BACKEND_CID=$($COMPOSE_PROD ps -q backend)
WORKER_CID=$($COMPOSE_PROD ps -q worker)

echo "-- waiting for backend healthy --"
for _ in $(seq 1 30); do
    STATUS=$(docker inspect -f '{{.State.Health.Status}}' "$BACKEND_CID" 2>/dev/null || echo "")
    [ "$STATUS" = "healthy" ] && break
    sleep 2
done
[ "$STATUS" = "healthy" ] || { echo "FAIL: backend never became healthy"; $COMPOSE_PROD logs backend; exit 1; }

echo "-- waiting for worker healthy --"
for _ in $(seq 1 30); do
    STATUS=$(docker inspect -f '{{.State.Health.Status}}' "$WORKER_CID" 2>/dev/null || echo "")
    [ "$STATUS" = "healthy" ] && break
    sleep 2
done
[ "$STATUS" = "healthy" ] || { echo "FAIL: worker never became healthy"; $COMPOSE_PROD logs worker; exit 1; }

echo "== P2.4: backup mechanism produces a valid, checksummed artifact against the running db container =="
# The backup pipeline's docker-exec transport (infra/db/backup) is
# designed to run from the *host* (a systemd timer, see
# deploy/saas-os-backup.service) -- never from inside a container, which
# has no docker socket (P2.3's own hardening). This check therefore uses
# the host's own Python, exactly as the real scheduled job would --
# skipping with a clear note (not failing the whole perimeter check) if
# this repository is not importable from the host interpreter, which is
# an environment-portability gap, not a P2.4 code defect.
DB_NAME=$(docker inspect --format '{{.Name}}' "$DB_CID" | sed 's#^/##')
if "$PY" -c "import infra.db.backup" >/dev/null 2>&1; then
    POSTGRES_USER="$(grep '^POSTGRES_USER=' .env | cut -d= -f2-)" \
    POSTGRES_PASSWORD="$(grep '^POSTGRES_PASSWORD=' .env | cut -d= -f2-)" \
    POSTGRES_DB="$(grep '^POSTGRES_DB=' .env | cut -d= -f2-)" \
    DB_CONTAINER_NAME="$DB_NAME" \
    "$PY" -c "
import os, tempfile
from pathlib import Path
from infra.db.config import DatabaseConfig
from infra.db.backup import create_backup, verify_backup_checksum

admin_config = DatabaseConfig(
    url=f'postgresql://{os.environ[\"POSTGRES_USER\"]}:{os.environ[\"POSTGRES_PASSWORD\"]}@ignored/{os.environ[\"POSTGRES_DB\"]}'
)
with tempfile.TemporaryDirectory() as tmp:
    metadata = create_backup(
        container=os.environ['DB_CONTAINER_NAME'],
        admin_config=admin_config,
        output_dir=Path(tmp),
        label='p24-check',
    )
    verify_backup_checksum(metadata.metadata_path)
    assert metadata.size_bytes > 0
    print(f'backup mechanism OK: {metadata.artifact_path.name} ({metadata.size_bytes} bytes, sha256={metadata.sha256[:12]}...)')
"
else
    echo "SKIP: host Python does not have this repository installed (pip install -e .) -- the backup mechanism's docker-exec transport is designed to run from the deployment host's own venv (see deploy/saas-os-backup.service), which this check environment does not reproduce. This is an environment-portability note, not a P2.4 code gap."
fi

echo "== start: proxy (Caddy) =="
PUBLIC_DOMAIN=localhost $COMPOSE_PROD up -d proxy
PROXY_CID=$($COMPOSE_PROD ps -q proxy)
for _ in $(seq 1 30); do
    STATUS=$(docker inspect -f '{{.State.Health.Status}}' "$PROXY_CID" 2>/dev/null || echo "")
    [ "$STATUS" = "healthy" ] && break
    sleep 2
done
[ "$STATUS" = "healthy" ] || { echo "FAIL: proxy never became healthy"; $COMPOSE_PROD logs proxy; exit 1; }

echo "== public port inventory: only 80/tcp and 443/tcp may be published =="
PUBLISHED=$(PUBLIC_DOMAIN=localhost $COMPOSE_PROD config --format json | "$PY" -c "
import json, sys
cfg = json.load(sys.stdin)
ports = []
for name, svc in cfg['services'].items():
    for p in svc.get('ports', []):
        published = p['published'] if isinstance(p, dict) else str(p).split(':')[0]
        ports.append(f'{name}:{published}')
print('\n'.join(sorted(ports)))
")
echo "$PUBLISHED"
EXTRA=$(echo "$PUBLISHED" | grep -vE ':80$|:443$' || true)
if [ -n "$EXTRA" ]; then
    echo "FAIL: a service publishes a port other than 80/443: $EXTRA"
    exit 1
fi
for FORBIDDEN in 5432 6379 8000 3000; do
    if echo "$PUBLISHED" | grep -q ":$FORBIDDEN\$"; then
        echo "FAIL: port $FORBIDDEN is published"
        exit 1
    fi
done
# docker port cross-check on the actually-running containers (not just the
# rendered config) for db/redis/backend/frontend individually.
for SERVICE in db redis backend frontend; do
    CID=$($COMPOSE_PROD ps -q "$SERVICE" 2>/dev/null || true)
    [ -z "$CID" ] && continue
    PORTMAP=$(docker port "$CID" 2>/dev/null || true)
    if [ -n "$PORTMAP" ]; then
        echo "FAIL: $SERVICE publishes a host port: $PORTMAP"
        exit 1
    fi
done

echo "== external boundary: PostgreSQL/Redis/backend/frontend unreachable from outside the stack =="
# Run from the host itself (a genuine "outside the stack" vantage point,
# not the false-positive of testing from inside the same Docker network)
# -- localhost:<port>, exactly where a published port would appear if one
# existed. Compared against the pre-startup baseline above: a port already
# reachable before this project started (an unrelated host service, e.g.
# a native PostgreSQL install) is reported as a known, pre-existing
# condition, never silently treated as a pass -- but a port that only
# became reachable AFTER this compose project started is an unambiguous
# FAIL, since that newly-reachable listener could only be this project's.
CURRENT_PORT_STATE=$("$PY" -c "
import socket
for port in (5432, 6379, 8000, 3000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(('127.0.0.1', port))
        print(f'{port}:reachable')
    except OSError:
        print(f'{port}:unreachable')
    finally:
        s.close()
")
echo "$CURRENT_PORT_STATE"
FAILED=0
for PORT in 5432 6379 8000 3000; do
    BEFORE=$(echo "$BASELINE_PORT_STATE" | grep "^$PORT:" | cut -d: -f2)
    AFTER=$(echo "$CURRENT_PORT_STATE" | grep "^$PORT:" | cut -d: -f2)
    if [ "$AFTER" = "unreachable" ]; then
        echo "port $PORT: unreachable (expected)"
    elif [ "$BEFORE" = "reachable" ]; then
        echo "port $PORT: reachable, but ALREADY reachable before this compose project started -- pre-existing, unrelated host service (see docker port / config checks above for the authoritative proof this project publishes nothing on it)"
    else
        echo "FAIL: port $PORT became reachable only after this compose project started"
        FAILED=1
    fi
done
[ "$FAILED" = "0" ] || exit 1

echo "== internal connectivity: backend/worker -> postgres, backend/worker -> redis =="
docker exec "$BACKEND_CID" python -c "
from infra.db.engine import build_engine
from infra.db.config import get_database_config
from sqlalchemy import text
engine = build_engine(get_database_config(), connect_args={'connect_timeout': 3})
with engine.connect() as conn:
    conn.execute(text('SELECT 1'))
print('backend -> postgres: OK')
"
docker exec "$WORKER_CID" python -c "
from infra.db.engine import build_engine
from infra.db.config import get_database_config
from sqlalchemy import text
engine = build_engine(get_database_config(), connect_args={'connect_timeout': 3})
with engine.connect() as conn:
    conn.execute(text('SELECT 1'))
print('worker -> postgres: OK')
"
docker exec "$BACKEND_CID" python -c "
import asyncio
from infra.jobs.queue import get_redis_pool
async def main():
    pool = await get_redis_pool()
    await pool.ping()
    await pool.aclose()
    print('backend -> redis: OK')
asyncio.run(main())
"

echo "== HTTP(80) -> HTTPS(443) redirect =="
REDIRECT=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://localhost:80/ --max-time 5)
echo "$REDIRECT"
case "$REDIRECT" in
    30*\ https://*) : ;;
    *) echo "FAIL: expected a 3xx redirect to https://, got: $REDIRECT"; exit 1 ;;
esac

echo "== TLS handshake succeeds (Caddy's internal CA for PUBLIC_DOMAIN=localhost -- NOT live ACME) =="
curl -sk -o /dev/null -w 'TLS handshake + HTTP %{http_code}\n' https://localhost:443/ --max-time 5

echo "== security headers present on the HTTPS response =="
HEADERS=$(curl -sk -D - -o /dev/null https://localhost:443/ --max-time 5)
echo "$HEADERS" | grep -qi '^strict-transport-security:' || { echo "FAIL: missing HSTS header"; exit 1; }
echo "$HEADERS" | grep -qi '^x-content-type-options: *nosniff' || { echo "FAIL: missing X-Content-Type-Options"; exit 1; }
echo "$HEADERS" | grep -qi '^referrer-policy:' || { echo "FAIL: missing Referrer-Policy"; exit 1; }

echo "== X-Request-ID is preserved through the proxy (backend-routed path -- api/middleware.py's own correlation header; the frontend/Next.js has no such header of its own to check) =="
RID=$(curl -sk -D - -o /dev/null -H 'X-Request-ID: p23-check-12345' https://localhost:443/auth/me --max-time 5 | grep -i '^x-request-id:' || true)
echo "$RID"
echo "$RID" | grep -q 'p23-check-12345' || { echo "FAIL: X-Request-ID was not preserved through the proxy"; exit 1; }

echo "== /healthz and /readyz are NOT proxied to the backend externally (fall through to frontend's own 404) =="
for PATH_ in /healthz /readyz; do
    CODE=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:443$PATH_" --max-time 5)
    if [ "$CODE" = "200" ]; then
        echo "FAIL: $PATH_ is externally reachable and returned 200 -- readiness internals must not be public"
        exit 1
    fi
    echo "$PATH_ -> $CODE (not 200, as required)"
done

echo "== backend readiness/liveness remain reachable INTERNALLY (docker exec, unchanged from P1.8) =="
docker exec "$BACKEND_CID" python -c \
    "import urllib.request as u; r = u.urlopen('http://127.0.0.1:8000/healthz', timeout=3); assert r.status == 200"
docker exec "$BACKEND_CID" python -c \
    "import urllib.request as u; r = u.urlopen('http://127.0.0.1:8000/readyz', timeout=3); assert r.status == 200"

echo "== /auth/* and /v1/* are reachable through the proxy, over HTTPS, same origin as the frontend =="
CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:443/auth/me --max-time 5)
[ "$CODE" = "401" ] || { echo "FAIL: expected 401 from /auth/me with no session, got $CODE"; exit 1; }
CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:443/v1/tenants/00000000-0000-0000-0000-000000000000/status --max-time 5)
[ "$CODE" = "401" ] || { echo "FAIL: expected 401 from /v1/... with no session, got $CODE"; exit 1; }
LOGIN_HEADERS=$(curl -sk -D - -o /dev/null https://localhost:443/auth/login --max-time 5)
echo "$LOGIN_HEADERS" | grep -qi '^location:' || echo "note: /auth/login has no OIDC provider configured in this check -- see auth flow integration tests for the full mocked-provider proof"

echo "== session cookie remains Secure over the proxy (set only on a real login; verified structurally by P2.2's own test suite; here we confirm AUTH_COOKIE_SECURE cannot be disabled in production config) =="
docker exec "$BACKEND_CID" python -c "
import os
os.environ['ENVIRONMENT'] = 'production'
os.environ['OIDC_REDIRECT_URI'] = 'https://localhost/auth/callback'
os.environ['AUTH_COOKIE_SECURE'] = 'false'
from api.auth.config import AuthConfigurationError, _auth_http_config_from_env
try:
    _auth_http_config_from_env()
    raise SystemExit('FAIL: production config accepted an insecure cookie setting')
except AuthConfigurationError:
    print('production config correctly refuses AUTH_COOKIE_SECURE=false')
"

echo "== forwarded-header trust: a spoofed X-Forwarded-For cannot bypass the auth rate limit =="
docker exec -e RATE_LIMIT_REQUESTS_PER_WINDOW=2 -e RATE_LIMIT_WINDOW_SECONDS=60 "$BACKEND_CID" python -c "
import asyncio
from unittest.mock import MagicMock
from api.auth.config import AuthHttpConfig
from api.auth.routes import _enforce_auth_rate_limit
from infra.ratelimit.config import get_ratelimit_config
from fastapi import HTTPException

get_ratelimit_config.cache_clear()
config = AuthHttpConfig(redirect_uri='https://localhost/auth/callback', trust_proxy_headers=True)

def request(forwarded_for):
    r = MagicMock()
    r.client = MagicMock(host='10.0.0.99')
    r.headers = {'X-Forwarded-For': forwarded_for}
    return r

async def main():
    real_hop = '203.0.113.55'
    await _enforce_auth_rate_limit(request(f'1.1.1.1, {real_hop}'), config=config)
    await _enforce_auth_rate_limit(request(f'2.2.2.2, {real_hop}'), config=config)
    try:
        await _enforce_auth_rate_limit(request(f'3.3.3.3, {real_hop}'), config=config)
        raise SystemExit('FAIL: a spoofed X-Forwarded-For prefix bypassed the rate limit')
    except HTTPException as exc:
        assert exc.status_code == 429
        print('spoofed X-Forwarded-For prefixes correctly share one rate-limit bucket')

asyncio.run(main())
"

echo "== worker: a real job enqueued from the backend is executed (P2.1 regression, this topology) =="
docker exec "$BACKEND_CID" python -c "
import asyncio, time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from core.tenancy import create_tenant
from core.usage import aggregate_usage, ingest_event
tenant = create_tenant('p23-docker-check-worker')
asyncio.run(ingest_event(tenant.id, 'p23_check', Decimal('1')))
since, until = datetime.now(UTC) - timedelta(minutes=5), datetime.now(UTC) + timedelta(minutes=5)
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    if aggregate_usage(tenant.id, 'p23_check', since=since, until=until) == Decimal('1'):
        print('worker executed the job'); raise SystemExit(0)
    time.sleep(0.5)
raise SystemExit('FAIL: the worker never executed the enqueued job')
"

echo "== no secret value in proxy logs or image history =="
SECRET_VALUES=$(grep -E '^(POSTGRES_PASSWORD|APP_DB_PASSWORD|STRIPE_API_KEY|STRIPE_WEBHOOK_SECRET|ZITADEL_CLIENT_SECRET|SMTP_PASSWORD)=' .env | cut -d= -f2- | grep -v '^$' || true)
PROXY_LOGS=$(docker logs "$PROXY_CID" 2>&1)
BACKEND_LOGS=$(docker logs "$BACKEND_CID" 2>&1)
for VALUE in $SECRET_VALUES; do
    if [[ "$PROXY_LOGS" == *"$VALUE"* ]] || [[ "$BACKEND_LOGS" == *"$VALUE"* ]]; then
        echo "FAIL: a secret value from .env appears in proxy or backend logs"
        exit 1
    fi
done
IMAGE_HISTORY=$(docker image history --no-trunc "$($COMPOSE_PROD images -q backend)" 2>&1)
for VALUE in $SECRET_VALUES; do
    if [[ "$IMAGE_HISTORY" == *"$VALUE"* ]]; then
        echo "FAIL: a secret value from .env appears in the backend image history"
        exit 1
    fi
done
if [[ "$PROXY_LOGS" == *"code="* ]] || [[ "$PROXY_LOGS" == *"Bearer "* ]]; then
    echo "FAIL: proxy access log appears to record an authentication query parameter or bearer token"
    exit 1
fi

echo "== graceful shutdown: proxy, backend, worker all exit cleanly on SIGTERM =="
$COMPOSE_PROD stop proxy backend worker
for SERVICE_CID in "$PROXY_CID" "$BACKEND_CID" "$WORKER_CID"; do
    EXIT_CODE=$(docker inspect -f '{{.State.ExitCode}}' "$SERVICE_CID")
    if [ "$EXIT_CODE" != "0" ]; then
        echo "FAIL: container $SERVICE_CID did not exit cleanly (exit code $EXIT_CODE)"
        exit 1
    fi
done

_cleanup
trap - EXIT

echo "All production perimeter checks passed."
echo "NOTE: TLS was validated using Caddy's internal CA (PUBLIC_DOMAIN=localhost)."
echo "Live ACME/DNS certificate issuance against a real, publicly-resolvable domain was NOT performed."
