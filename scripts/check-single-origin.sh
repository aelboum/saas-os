#!/usr/bin/env bash
# ADR-0024 -- runtime validation of the single-origin application runtime.
# Kept OUT of check-all.sh for the same reason check-docker.sh is: it builds
# images and starts real containers (slow, needs a Docker daemon), unlike
# the fast deterministic checks. Run explicitly.
#
# Proves, against the real stack rather than against configuration text:
#   - edge, backend, frontend and the local ZITADEL all start
#   - /readyz answers 200 through the public origin
#   - /auth/me and /v1/* reach the BACKEND through the public origin
#   - a normal browser path reaches the FRONTEND, not the backend
#   - ZITADEL's own admin/management routes have no route through the edge
#   - OIDC discovery works
#   - the callback derives from the public origin, and /auth/login 303s to
#     the provider with that redirect_uri and PKCE S256
#
# No credential is entered anywhere: the flow is verified up to the
# provider's own login page, which is where automation stops.
#
# Everything runs in an isolated Compose project (-p), with host port
# publication reset off (local-dev/compose.no-host-ports.yml), and is torn
# down at the end. Every HTTP probe is made from INSIDE the Compose network
# (`docker exec` against `http://edge:8080`), never against a host port --
# the same "do not depend on host ports" discipline check-docker.sh keeps,
# so this cannot collide with a developer's own running stack or with an
# unrelated project on the same machine. Host publication itself is asserted
# structurally by tests/architecture/test_single_origin_edge.py.
#
# `docker compose config` is never run here: docker-compose.yml's services
# resolve `.env`, and rendering it would print those values.
set -euo pipefail
cd "$(dirname "$0")/.."

# Git Bash/MSYS rewrites any argument that looks like a POSIX path into a
# Windows one before the process sees it, which turns `docker exec ... /readyz`
# into `.../Program Files/Git/readyz` (verified empirically on this
# repository's own Windows toolchain). Both variables are MSYS-only and
# inert everywhere else, so this stays a single portable script.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

# Same placeholder-only bootstrap every other Docker check uses: Compose
# needs *a* .env to parse docker-compose.yml at all. A real .env is never
# overwritten, and one created here is removed again.
CREATED_ENV=""
if [ ! -f .env ]; then
    cp .env.example .env
    CREATED_ENV=1
fi

# The origin the check drives the stack with. Pinned by the override file
# rather than read from `.env`, so the result does not depend on whatever a
# developer happens to have configured -- including a pre-ADR-0024 `.env`
# that sets `OIDC_REDIRECT_URI` and no origin at all, which remains
# supported and is covered by the unit tests instead. Probes themselves
# reach the edge over the Compose network; this value is what the backend's
# own derived callback must equal.
PUBLIC_APP_ORIGIN="http://localhost:8080"

COMPOSE="docker compose -p saas-os-check-single-origin -f docker-compose.yml -f local-dev/compose.no-host-ports.yml"
_cleanup() {
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
    if [ -n "$CREATED_ENV" ]; then
        rm -f .env
    fi
    return 0
}
trap _cleanup EXIT

echo "== bringing up the single-origin stack (edge + backend + frontend + local identity) =="
$COMPOSE up -d --build db redis backend frontend edge zitadel-db zitadel

_wait_healthy() {
    local service="$1" cid status
    cid=$($COMPOSE ps -q "$service")
    status=""
    for _ in $(seq 1 60); do
        status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo "")
        if [ "$status" = "healthy" ] || [ "$status" = "running" ]; then
            return 0
        fi
        sleep 2
    done
    echo "FAIL: $service never became healthy (last status: ${status:-unknown})"
    $COMPOSE logs --tail 50 "$service" || true
    exit 1
}

for SERVICE in db redis backend frontend edge zitadel; do
    echo "-- waiting for $SERVICE --"
    _wait_healthy "$SERVICE"
done

BACKEND_CID=$($COMPOSE ps -q backend)

# The disposable database starts with only the role-creation init script
# applied; `/auth/login` writes a real `core.login_transactions` row, so the
# repository's own Alembic chain is applied first -- through the migration
# role, from inside the backend container, exactly as check-docker.sh does
# for the same reason (alembic.ini is a repo-root file deliberately not
# copied into the image, so the script location is given programmatically).
echo "== applying migrations to the disposable database =="
docker exec "$BACKEND_CID" python -c "
from alembic import command
from alembic.config import Config
config = Config()
config.set_main_option('script_location', 'saas_os/infra/db/migrations')
command.upgrade(config, 'head')
" >/dev/null

# One probe helper, run inside the backend container against the edge's own
# service address. Prints "<status>|<first 200 bytes of body>".
_probe() {
    docker exec "$BACKEND_CID" python -c "
import sys, urllib.request as u, urllib.error
request = u.Request('http://edge:8080' + sys.argv[1])
try:
    with u.urlopen(request, timeout=15) as response:
        status, body = response.status, response.read(200)
except urllib.error.HTTPError as exc:
    status, body = exc.code, exc.read(200)
print(f'{status}|' + body.decode('utf-8', 'replace').replace(chr(10), ' '))
" "$1"
}

_status() { _probe "$1" | cut -d'|' -f1; }

echo "== /readyz answers through the edge =="
CODE=""
for _ in $(seq 1 30); do
    CODE=$(_status /readyz || echo "000")
    [ "$CODE" = "200" ] && break
    sleep 2
done
[ "$CODE" = "200" ] || { echo "FAIL: expected 200 from /readyz through the edge, got $CODE"; exit 1; }

echo "== /v1/* reaches the backend through the edge (401, not a frontend 404) =="
CODE=$(_status /v1/tenants/00000000-0000-0000-0000-000000000000/status)
[ "$CODE" = "401" ] || { echo "FAIL: expected 401 from /v1/... through the edge, got $CODE"; exit 1; }

echo "== /auth/me reaches the backend through the edge =="
CODE=$(_status /auth/me)
[ "$CODE" = "401" ] || { echo "FAIL: expected 401 from /auth/me through the edge, got $CODE"; exit 1; }

echo "== a normal browser path reaches the frontend, not the backend =="
ROOT=$(_probe /)
case "$ROOT" in
    *"<html"*|*"<!DOCTYPE"*|*"<!doctype"*) ;;
    *) echo "FAIL: / did not return an HTML document from the frontend"; exit 1 ;;
esac
# A product route SaaS-OS knows nothing about must reach the frontend. The
# backend answers unknown paths with its own JSON 404 body, so that body
# appearing here would mean the edge is routing too broadly.
PRODUCT_ROUTE=$(_probe /some/product/route)
case "$PRODUCT_ROUTE" in
    *'"detail"'*)
        echo "FAIL: an unknown path was answered by the BACKEND -- the edge routes too broadly"
        exit 1 ;;
esac

echo "== no internal service is reachable through the edge =="
for INTERNAL_PATH in /management/v1/orgs/me /ui/console /debug/ready /oauth/v2/token; do
    RESPONSE=$(_probe "$INTERNAL_PATH")
    case "$RESPONSE" in
        *'"org"'*|*ZITADEL*|*zitadel*)
            echo "FAIL: $INTERNAL_PATH reached ZITADEL through the application edge"
            exit 1 ;;
    esac
done
# Structural, not probe-based: the edge's own mounted configuration must
# name no upstream other than the two application services.
EDGE_CID=$($COMPOSE ps -q edge)
if docker exec "$EDGE_CID" grep -E '^\s*reverse_proxy' /etc/caddy/Caddyfile | grep -qvE 'backend|frontend'; then
    echo "FAIL: the edge proxies something other than the backend/frontend services"
    exit 1
fi

echo "== OIDC discovery works from the backend =="
docker exec "$BACKEND_CID" python -c "
import os, urllib.request as u
issuer = os.environ['OIDC_ISSUER_URL'].rstrip('/')
with u.urlopen(issuer + '/.well-known/openid-configuration', timeout=15) as response:
    assert response.status == 200, response.status
print('OIDC discovery document served by the local provider')
"

echo "== the callback derives from the public origin =="
docker exec -e EXPECTED_ORIGIN="$PUBLIC_APP_ORIGIN" "$BACKEND_CID" python -c "
import os
from saas_os.api.auth.config import get_auth_http_config
config = get_auth_http_config()
expected = os.environ['EXPECTED_ORIGIN'].rstrip('/') + '/auth/callback'
assert config.redirect_uri == expected, (config.redirect_uri, expected)
assert config.post_login_path.startswith('/') and '://' not in config.post_login_path
print('redirect_uri derived from PUBLIC_APP_ORIGIN:', config.redirect_uri)
print('post-login destination is a fixed same-origin path:', config.post_login_path)
"

echo "== the local OIDC application is bootstrapped against that same callback =="
$COMPOSE up -d zitadel-bootstrap
$COMPOSE wait zitadel-bootstrap >/dev/null 2>&1 || true
BOOTSTRAP_LOG=$($COMPOSE logs zitadel-bootstrap 2>/dev/null || true)
case "$BOOTSTRAP_LOG" in
    *"${PUBLIC_APP_ORIGIN}/auth/callback"*) ;;
    *)
        echo "FAIL: zitadel-bootstrap did not register ${PUBLIC_APP_ORIGIN}/auth/callback"
        echo "$BOOTSTRAP_LOG" | tail -10
        exit 1 ;;
esac
CLIENT_ID=$(printf '%s' "$BOOTSTRAP_LOG" | grep -oE 'OIDC_CLIENT_ID=[0-9]+' | tail -1 | cut -d= -f2 || true)
[ -n "$CLIENT_ID" ] || { echo "FAIL: zitadel-bootstrap printed no OIDC_CLIENT_ID"; exit 1; }

echo "== /auth/login redirects to the provider, same origin in, provider out =="
# The backend needs the provider-assigned client id this run's bootstrap
# produced. Exported into Compose's own interpolation for one service
# re-create (see local-dev/compose.no-host-ports.yml) -- no `.env` is read
# or written for it.
SAAS_OS_CHECK_OIDC_CLIENT_ID="$CLIENT_ID" $COMPOSE up -d --force-recreate backend
_wait_healthy backend
BACKEND_CID=$($COMPOSE ps -q backend)

LOCATION=$(docker exec "$BACKEND_CID" python -c "
import urllib.request as u, urllib.error
class _NoRedirect(u.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
opener = u.build_opener(_NoRedirect)
try:
    response = opener.open('http://edge:8080/auth/login', timeout=20)
    print('NO-REDIRECT status', response.status)
except urllib.error.HTTPError as exc:
    location = exc.headers.get('location')
    print(location or f'NO-REDIRECT status {exc.code}: ' + exc.read(200).decode('utf-8', 'replace'))
")
case "$LOCATION" in
    *zitadel.localhost*) ;;
    *) echo "FAIL: /auth/login did not redirect to the identity provider (got: ${LOCATION:-<none>})"; exit 1 ;;
esac
case "$LOCATION" in
    *"code_challenge_method=S256"*) ;;
    *) echo "FAIL: the authorization request does not use PKCE S256"; exit 1 ;;
esac
ENCODED_CALLBACK=$(printf '%s' "${PUBLIC_APP_ORIGIN}/auth/callback" | sed 's|:|%3A|g; s|/|%2F|g')
case "$LOCATION" in
    *"$ENCODED_CALLBACK"*) ;;
    *) echo "FAIL: the authorization request's redirect_uri is not on the public origin"; exit 1 ;;
esac
echo "-- /auth/login -> provider, PKCE S256, redirect_uri on $PUBLIC_APP_ORIGIN --"
echo "-- the provider's own login page is where automation stops; no credential is entered --"

echo "All single-origin runtime checks passed."
