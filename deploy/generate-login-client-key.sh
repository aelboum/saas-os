#!/bin/sh
# ADR-0025 §7 (Decision 4): the ZITADEL Login V2 service authenticates to the
# ZITADEL API with a system-user JWT (ZITADEL v4.19.0
# self-hosting/manage/adopt-login-v2.mdx §2; system-user key format per
# guides/integrate/zitadel-apis/access-zitadel-system-api.mdx). This one-shot
# script creates that RSA keypair at deploy time, the same runtime-generated
# pattern deploy/generate-identity-tls-cert.sh already uses -- no key is ever
# committed to Git, written into Compose, or placed in .env.
#
# Split across two volumes so each side only ever sees its own half:
#   /login-client-private/login-client.pem  -- mounted ONLY into
#       `zitadel-login` (read-only), owned by that image's runtime user
#       (uid/gid 1001, `nextjs`), mode 0400.
#   /login-client-public/login-client.pub   -- mounted ONLY into `zitadel`,
#       referenced by deploy/zitadel-login-client-system-user.yaml.
# SaaS-OS services (backend/worker/frontend) never mount either volume.
#
# Idempotent: an existing keypair is kept. Rotation is a deliberate operator
# action -- remove both files (or both volumes) and restart `zitadel` and
# `zitadel-login` so ZITADEL picks up the new public key.
set -eu

PRIVATE_DIR="/login-client-private"
PUBLIC_DIR="/login-client-public"
PRIVATE_KEY="$PRIVATE_DIR/login-client.pem"
PUBLIC_KEY="$PUBLIC_DIR/login-client.pub"
LOGIN_UID=1001
LOGIN_GID=1001

mkdir -p "$PRIVATE_DIR" "$PUBLIC_DIR"

if [ ! -f "$PRIVATE_KEY" ] || [ ! -f "$PUBLIC_KEY" ]; then
    umask 077
    openssl genrsa -traditional -out "$PRIVATE_KEY" 2048
    openssl rsa -in "$PRIVATE_KEY" -outform PEM -pubout -out "$PUBLIC_KEY"
fi

chown "$LOGIN_UID:$LOGIN_GID" "$PRIVATE_KEY"
chmod 0400 "$PRIVATE_KEY"
chmod 0444 "$PUBLIC_KEY"

echo "login-client system-user keypair ready (private key never leaves the zitadel-login volume)"
