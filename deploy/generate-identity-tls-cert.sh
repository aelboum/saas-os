#!/bin/sh
# ADR-0023 Phase 3 -- run once, by the `identity-tls-init` one-shot service
# in docker-compose.prod.yml, before `zitadel` ever starts.
#
# Why this exists: `backend`/`zitadel-bootstrap` reach ZITADEL directly over
# the `identity-edge` network, via a Docker network alias equal to
# IDENTITY_PUBLIC_DOMAIN (avoiding a Caddy hairpin) -- but the exact same
# URL (https://<IDENTITY_PUBLIC_DOMAIN>) is also what the browser uses
# through Caddy, so whatever answers on that alias must actually speak TLS,
# not just claim to over a plaintext connection. ZITADEL terminates that
# TLS itself for this internal-facing listener (its own documented
# "enabled-tls" reverse-proxy pattern -- zitadel.com/docs/self-hosting/
# manage/reverseproxy/caddy) using a self-signed certificate this script
# generates. Caddy's own leg to ZITADEL trusts it via
# `transport http { tls_insecure_skip_verify }` in the existing-deployment
# profile (ZITADEL's own documented pattern for exactly this) and verifies it
# against this certificate (`identity-ca`) in the fresh-deployment profile
# (ADR-0025 §1a, deploy/caddy/); `zitadel-login` trusts it via
# SSL_CERT_DIR=/identity-ca; `backend`/`zitadel-bootstrap` trust it via the
# standard `SSL_CERT_FILE` environment variable, which both `httpx`'s and
# `urllib.request`'s default TLS verification already honor -- verified
# empirically against the pinned v4.19.0 image -- so no `saas_os/core/identity` or
# `local-dev` code needed any change for this to work.
#
# Idempotent: a re-run (e.g. every `docker compose up`) reuses an
# already-generated certificate rather than rotating it on every restart --
# ZITADEL itself would otherwise need re-pointing at a new cert on every
# deploy for no operational benefit. Delete the `identity-tls-server`/
# `identity-ca` volumes to force regeneration.
#
# Two volumes, not one: `identity-tls-server` (certificate AND private key)
# is mounted only into `zitadel`; `identity-ca` (certificate only, copied
# from the same cert, no key) is mounted read-only into `backend`/
# `zitadel-bootstrap` -- neither of which has, or needs, ZITADEL's own TLS
# private key.
set -eu

SERVER_DIR="/identity-tls-server"
CA_DIR="/identity-ca"
DOMAIN="${IDENTITY_PUBLIC_DOMAIN:?IDENTITY_PUBLIC_DOMAIN must be set}"

mkdir -p "$SERVER_DIR" "$CA_DIR"

if [ ! -f "$SERVER_DIR/tls.crt" ] || [ ! -f "$SERVER_DIR/tls.key" ]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$SERVER_DIR/tls.key" \
        -out "$SERVER_DIR/tls.crt" \
        -days 3650 -nodes \
        -subj "/CN=${DOMAIN}" \
        -addext "subjectAltName=DNS:${DOMAIN}"
fi

cp "$SERVER_DIR/tls.crt" "$CA_DIR/tls.crt"

# World-readable: ZITADEL's own container image runs as a non-root,
# fixed-UID user with no shell/chown available to fix this up itself
# (the same constraint `zitadel-bootstrap-vol-init`'s own comment already
# documents for the PAT volume, in both docker-compose.yml and this file's
# own sibling service below) -- this volume is reachable only from
# `zitadel` itself plus this one-shot init container, on networks/mounts
# no other service joins, so world-readable-within-that-boundary is the
# same accepted trade-off, not a new one.
chmod 0644 "$SERVER_DIR/tls.crt" "$SERVER_DIR/tls.key" "$CA_DIR/tls.crt"

echo "identity TLS material ready for ${DOMAIN}"
