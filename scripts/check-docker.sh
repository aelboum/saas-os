#!/usr/bin/env bash
# Docker build + runtime validation. Kept OUT of check-all.sh -- these are
# slow (image builds take tens of seconds) and require a running Docker
# daemon, unlike the fast, deterministic checks in check-backend.sh /
# check-frontend.sh / check-security.sh. Run explicitly, or via the CI
# `docker` job. docs/IMPLEMENTATION-ROADMAP.md Phase 1.4.
#
# Never publishes a host port and uses an isolated Compose project name
# (-p), so this cannot conflict with unrelated containers/projects that
# might already be running on the same machine.
#
# `docker-compose.yml`'s services declare `env_file: .env`, so `docker
# compose config` needs *a* .env to exist -- CI (and a fresh checkout) has
# none, and must not require a real one (docs/ADR/0012-secrets-management.md:
# CI must not require production secrets). If absent, .env.example (all
# placeholder values, no real secret) is copied in; an existing real .env
# is never touched.
set -euo pipefail
cd "$(dirname "$0")/.."

BACKEND_TAG="saas-os-backend:check"
FRONTEND_TAG="saas-os-frontend:check"

echo "== docker build: backend =="
docker build -t "$BACKEND_TAG" .

echo "== docker build: frontend =="
docker build -t "$FRONTEND_TAG" ./frontend

echo "== docker run: backend (P1.8 real ASGI server, against disposable db+redis; no host ports) =="
# `docker compose` needs *a* .env to parse docker-compose.yml at all (its
# `backend`/`frontend` services declare `env_file: .env`) -- same
# placeholder-only bootstrap the `docker compose config` step below
# already relies on, just done earlier since this section now also uses
# `docker compose`.
[ -f .env ] || cp .env.example .env
# The backend's own P1.2 startup guard (infra/db/role_guard.py) requires a
# reachable PostgreSQL during lifespan startup -- unlike the old
# import-smoke placeholder, the real server cannot start in total
# isolation. An isolated Compose project (-p) brings up disposable
# `db`/`redis` only (never `frontend`) and the same `Dockerfile`-built
# backend image, all torn down at the end via the trap below -- never the
# developer's own persistent `saas-os-db-1`/`saas-os-redis-1`.
COMPOSE_RUNTIME="docker compose -p saas-os-check-runtime"
_runtime_cleanup() {
    $COMPOSE_RUNTIME down -v --remove-orphans >/dev/null 2>&1 || true
}
trap _runtime_cleanup EXIT

$COMPOSE_RUNTIME up -d db redis
$COMPOSE_RUNTIME build backend
$COMPOSE_RUNTIME up -d backend

echo "-- waiting for the backend container to report healthy (Dockerfile HEALTHCHECK) --"
BACKEND_CID=$($COMPOSE_RUNTIME ps -q backend)
HEALTHY=""
for _ in $(seq 1 30); do
    STATUS=$(docker inspect -f '{{.State.Health.Status}}' "$BACKEND_CID" 2>/dev/null || echo "")
    if [ "$STATUS" = "healthy" ]; then
        HEALTHY=1
        break
    fi
    sleep 2
done
if [ -z "$HEALTHY" ]; then
    echo "FAIL: backend did not become healthy"
    $COMPOSE_RUNTIME logs backend || true
    exit 1
fi

echo "-- liveness (200) --"
docker exec "$BACKEND_CID" python -c \
    "import urllib.request as u; r = u.urlopen('http://127.0.0.1:8000/healthz', timeout=3); assert r.status == 200, r.status"

echo "-- readiness (200, dependencies up) --"
docker exec "$BACKEND_CID" python -c \
    "import urllib.request as u; r = u.urlopen('http://127.0.0.1:8000/readyz', timeout=3); assert r.status == 200, r.status"

echo "-- representative existing API route responds through the real server (401, no auth) --"
docker exec "$BACKEND_CID" python -c "
import urllib.request as u, urllib.error
try:
    u.urlopen('http://127.0.0.1:8000/v1/tenants/00000000-0000-0000-0000-000000000000/status', timeout=3)
    raise SystemExit('expected 401')
except urllib.error.HTTPError as e:
    assert e.code == 401, e.code
    assert e.headers.get('x-request-id')
"

echo "-- readiness becomes 503 (no secret/exception leak) when PostgreSQL is unavailable; liveness stays 200 --"
$COMPOSE_RUNTIME stop db >/dev/null
sleep 2
docker exec "$BACKEND_CID" python -c "
import urllib.request as u, urllib.error
try:
    u.urlopen('http://127.0.0.1:8000/readyz', timeout=3)
    raise SystemExit('expected 503')
except urllib.error.HTTPError as e:
    assert e.code == 503, e.code
    body = e.read().decode()
    assert 'DATABASE_URL' not in body and 'postgresql://' not in body and 'saas_os' not in body
"
docker exec "$BACKEND_CID" python -c \
    "import urllib.request as u; r = u.urlopen('http://127.0.0.1:8000/healthz', timeout=3); assert r.status == 200, r.status"
$COMPOSE_RUNTIME start db >/dev/null

echo "-- container remains running throughout --"
RUNNING=$(docker ps --filter "id=$BACKEND_CID" --filter "status=running" --format '{{.ID}}')
if [ -z "$RUNNING" ]; then
    echo "FAIL: backend container is not running"
    exit 1
fi

echo "== docker run: worker (P2.1 real ARQ worker, same image, no host ports) =="
# The disposable db has only the role-creation init script applied; the
# worker's jobs write real Core tables, so the repository's own Alembic
# chain is applied first -- through the migration/admin role
# (MIGRATIONS_DATABASE_URL), exactly as a deploy would, from inside the
# backend container (the image carries infra/db/migrations; alembic.ini
# is a repo-root file deliberately not copied into the image, so the
# script location is given programmatically).
docker exec "$BACKEND_CID" python -c "
from alembic import command
from alembic.config import Config
cfg = Config()
cfg.set_main_option('script_location', 'infra/db/migrations')
command.upgrade(cfg, 'head')
"
$COMPOSE_RUNTIME up -d worker
WORKER_CID=$($COMPOSE_RUNTIME ps -q worker)

echo "-- waiting for the worker container to report healthy (arq health sentinel via 'python -m api.worker --check') --"
WORKER_HEALTHY=""
for _ in $(seq 1 30); do
    STATUS=$(docker inspect -f '{{.State.Health.Status}}' "$WORKER_CID" 2>/dev/null || echo "")
    if [ "$STATUS" = "healthy" ]; then
        WORKER_HEALTHY=1
        break
    fi
    sleep 2
done
if [ -z "$WORKER_HEALTHY" ]; then
    echo "FAIL: worker container never became healthy"
    docker logs "$WORKER_CID" || true
    exit 1
fi

echo "-- worker publishes no host port --"
if [ -n "$(docker port "$WORKER_CID")" ]; then
    echo "FAIL: worker container publishes a host port: $(docker port "$WORKER_CID")"
    exit 1
fi

echo "-- a real job enqueued from the backend container is executed by the worker --"
# core.usage.ingest_event() enqueues onto arq's default queue (the one the
# worker consumes); the worker's registered handler inserts the row through
# tenant_session_scope() as the restricted app role. aggregate_usage()
# reading 1 back proves the full enqueue -> Redis -> worker -> RLS-scoped
# write -> success path, not merely that a process is running.
docker exec "$BACKEND_CID" python -c "
import asyncio, time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from core.tenancy import create_tenant
from core.usage import aggregate_usage, ingest_event
tenant = create_tenant('docker-check-worker')
asyncio.run(ingest_event(tenant.id, 'docker_check', Decimal('1')))
since, until = datetime.now(UTC) - timedelta(minutes=5), datetime.now(UTC) + timedelta(minutes=5)
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    if aggregate_usage(tenant.id, 'docker_check', since=since, until=until) == Decimal('1'):
        print('worker executed the job'); raise SystemExit(0)
    time.sleep(0.5)
raise SystemExit('FAIL: the worker never executed the enqueued job')
"

echo "-- no secret value in the worker's logs or the image history; worker env introduces no new variable beyond backend's --"
SECRET_VALUES=$(grep -E '^(POSTGRES_PASSWORD|APP_DB_PASSWORD|STRIPE_API_KEY|STRIPE_WEBHOOK_SECRET|ZITADEL_CLIENT_SECRET|SMTP_PASSWORD)=' .env | cut -d= -f2- | grep -v '^$' || true)
WORKER_LOGS=$(docker logs "$WORKER_CID" 2>&1)
IMAGE_HISTORY=$(docker image history --no-trunc "$BACKEND_TAG" 2>&1)
for VALUE in $SECRET_VALUES; do
    if [[ "$WORKER_LOGS" == *"$VALUE"* ]]; then
        echo "FAIL: a secret value from .env appears in the worker logs"
        exit 1
    fi
    if [[ "$IMAGE_HISTORY" == *"$VALUE"* ]]; then
        echo "FAIL: a secret value from .env appears in the image history"
        exit 1
    fi
done
BACKEND_ENV_KEYS=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$BACKEND_CID" | cut -d= -f1 | sort)
WORKER_ENV_KEYS=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$WORKER_CID" | cut -d= -f1 | sort)
if [ "$BACKEND_ENV_KEYS" != "$WORKER_ENV_KEYS" ]; then
    echo "FAIL: the worker container's environment variable set differs from the backend's"
    diff <(echo "$BACKEND_ENV_KEYS") <(echo "$WORKER_ENV_KEYS") || true
    exit 1
fi

echo "-- worker clean shutdown (SIGTERM, exit 0) --"
$COMPOSE_RUNTIME stop worker
WORKER_EXIT=$(docker inspect -f '{{.State.ExitCode}}' "$WORKER_CID")
if [ "$WORKER_EXIT" != "0" ]; then
    echo "FAIL: worker did not exit cleanly on SIGTERM (exit code $WORKER_EXIT)"
    docker logs "$WORKER_CID" || true
    exit 1
fi

echo "-- clean shutdown (SIGTERM, exit 0) --"
$COMPOSE_RUNTIME stop backend
EXIT_CODE=$(docker inspect -f '{{.State.ExitCode}}' "$BACKEND_CID")
if [ "$EXIT_CODE" != "0" ]; then
    echo "FAIL: backend did not exit cleanly on SIGTERM (exit code $EXIT_CODE)"
    exit 1
fi

_runtime_cleanup
trap - EXIT

echo "== docker run: frontend (starts, checked, stopped -- no host port published) =="
# Output is captured into variables (not piped live into grep -q) --
# `grep -q` closes its input as soon as it matches, which under `pipefail`
# can SIGPIPE the writer and make the pipeline report failure even though
# the match succeeded. Command substitution avoids that race entirely.
CID=$(docker run -d "$FRONTEND_TAG")
sleep 5
RUNNING=$(docker ps --filter "id=$CID" --filter "status=running" --format '{{.ID}}')
if [ -z "$RUNNING" ]; then
    echo "FAIL: frontend container is not running after startup"
    docker logs "$CID" || true
    docker rm -f "$CID" >/dev/null 2>&1 || true
    exit 1
fi
LOGS=$(docker logs "$CID" 2>&1)
if [[ "$LOGS" != *"Ready"* ]]; then
    echo "FAIL: frontend did not report Ready"
    echo "$LOGS"
    docker rm -f "$CID" >/dev/null 2>&1 || true
    exit 1
fi
docker rm -f "$CID" >/dev/null

echo "== docker compose config (isolated project name, no containers started) =="
[ -f .env ] || cp .env.example .env
docker compose -p saas-os-check config >/dev/null

echo "All Docker checks passed."
