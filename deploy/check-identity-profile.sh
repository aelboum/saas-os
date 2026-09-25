#!/bin/sh
# ADR-0025 §1a: fail-closed guard for the two supported identity deployment
# profiles. Runs as a one-shot service (docker-compose.prod.yml's own
# `identity-profile-guard`) before any identity TLS material is generated and
# before ZITADEL starts.
#
#   fresh    -- canonical Topology A: ZITADEL (ExternalDomain, OIDC issuer,
#               Login V2, WebAuthn/U2F RP ID) on PUBLIC_DOMAIN itself, so
#               IDENTITY_PUBLIC_DOMAIN must equal PUBLIC_DOMAIN.
#   existing -- compatibility profile: ZITADEL stays on its own
#               IDENTITY_PUBLIC_DOMAIN (ADR-0023 §9), keeping the existing
#               issuer and RP ID, so the two domains must differ.
#
# ADR-0025 forbids any *automatic* issuer/RP-ID migration: WebAuthn/passkey
# and U2F credentials are scoped to the RP ID they were enrolled under, and
# SaaS-OS keys identities by (issuer, subject). This guard therefore pins the
# profile and both domains on first run (a small state volume) and refuses to
# start on any later change. A deployment that predates this guard is
# recognized by its existing identity TLS certificate (always generated for,
# and never regenerated away from, the domain ZITADEL was first deployed
# with -- deploy/generate-identity-tls-cert.sh); its domain must match too.
#
# If neither the pin nor that certificate exists, but ZITADEL's own database
# volume already holds an initialized PostgreSQL cluster (`PG_VERSION`, which
# initdb writes), an identity deployment -- its issuer and every passkey/U2F
# credential -- already exists under domains this guard can no longer
# confirm. That uncertainty is never treated as permission: the guard refuses
# to start, for either profile. (`zitadel-db` starts only after this guard,
# so a brand-new deployment is always pinned before that file can exist.)
# Changing any of these values is a separately approved migration project
# (ADR-0025 §1a), never a configuration edit this guard lets through.
set -eu

STATE_DIR="/identity-profile-state"
STATE_FILE="$STATE_DIR/profile"
EXISTING_CERT="/identity-tls-server/tls.crt"
EXISTING_ZITADEL_DB="/zitadel-db-data/PG_VERSION"

PROFILE="${IDENTITY_PROFILE:?IDENTITY_PROFILE must be set (fresh or existing)}"
PUBLIC="${PUBLIC_DOMAIN:?PUBLIC_DOMAIN must be set}"
IDENTITY="${IDENTITY_PUBLIC_DOMAIN:?IDENTITY_PUBLIC_DOMAIN must be set}"

fail() {
    echo "identity-profile-guard: REFUSING TO START: $1" >&2
    echo "identity-profile-guard: see docs/ADR/0025-same-origin-zitadel-login-v2-topology.md §1a" >&2
    exit 1
}

case "$PROFILE" in
    fresh)
        [ "$IDENTITY" = "$PUBLIC" ] || fail "IDENTITY_PROFILE=fresh requires IDENTITY_PUBLIC_DOMAIN ($IDENTITY) to equal PUBLIC_DOMAIN ($PUBLIC)"
        ;;
    existing)
        [ "$IDENTITY" != "$PUBLIC" ] || fail "IDENTITY_PROFILE=existing requires IDENTITY_PUBLIC_DOMAIN to differ from PUBLIC_DOMAIN ($PUBLIC)"
        ;;
    *)
        fail "IDENTITY_PROFILE must be 'fresh' or 'existing', got '$PROFILE'"
        ;;
esac

CURRENT="profile=$PROFILE public_domain=$PUBLIC identity_public_domain=$IDENTITY"

if [ -f "$STATE_FILE" ]; then
    PINNED="$(cat "$STATE_FILE")"
    [ "$PINNED" = "$CURRENT" ] || fail "identity deployment was pinned as '$PINNED' but is now configured as '$CURRENT'; an issuer/RP-ID change is not an automatic migration"
    echo "identity-profile-guard: OK ($CURRENT, pinned)"
    exit 0
fi

if [ -f "$EXISTING_CERT" ]; then
    CERT_SUBJECT="$(openssl x509 -in "$EXISTING_CERT" -noout -subject)"
    case "$CERT_SUBJECT" in
        *"CN = $IDENTITY"|*"CN=$IDENTITY") ;;
        *) fail "an existing identity deployment was found for a different domain ($CERT_SUBJECT); IDENTITY_PUBLIC_DOMAIN=$IDENTITY would change the existing issuer and RP ID" ;;
    esac
elif [ -f "$EXISTING_ZITADEL_DB" ]; then
    fail "an existing ZITADEL database was found, but neither the pinned identity profile nor the identity TLS certificate is present to confirm its domains; restore the identity-profile-state or identity-tls-server volume from backup -- starting with '$CURRENT' could change the existing issuer and RP ID"
fi

mkdir -p "$STATE_DIR"
printf '%s' "$CURRENT" > "$STATE_FILE"
chmod 0644 "$STATE_FILE"
echo "identity-profile-guard: OK ($CURRENT, pinned on first run)"
