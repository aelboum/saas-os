#!/usr/bin/env bash
# Creates the platform-configuration login role
# (docs/ADR/0056-platform-configuration-database-identity.md). This is what
# PLATFORM_CONFIG_DATABASE_URL points at: the only role that may write the
# global AI configuration tables. The application role (01-create-app-role.sh)
# may only read them.
#
# Runs automatically, once, via the official postgres image's own
# /docker-entrypoint-initdb.d mechanism -- only on first boot of a brand new
# (empty) data volume. Optional: without PLATFORM_CONFIG_DB_PASSWORD it does
# nothing, and the migration creates the role NOLOGIN instead (AI
# configuration writes then stay impossible until an operator enables the
# role, docs/RUNBOOKS.md). Idempotent (IF NOT EXISTS). The privileges
# themselves are granted by migration f6a2c8e4b1d9, not here.
#
# $PLATFORM_CONFIG_DB_USER / $PLATFORM_CONFIG_DB_PASSWORD come from
# docker-compose's environment, sourced from .env (gitignored, never
# committed). The password is never printed or persisted by this script.

set -euo pipefail

if [ -z "${PLATFORM_CONFIG_DB_PASSWORD:-}" ]; then
    echo "PLATFORM_CONFIG_DB_PASSWORD not set; platform-configuration login role not created."
    exit 0
fi
PLATFORM_CONFIG_DB_USER="${PLATFORM_CONFIG_DB_USER:-saas_os_platform_config}"
if ! [[ "$PLATFORM_CONFIG_DB_USER" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "PLATFORM_CONFIG_DB_USER must be a plain SQL identifier." >&2
    exit 1
fi
if [ "$PLATFORM_CONFIG_DB_USER" = "${APP_DB_USER:-}" ]; then
    echo "PLATFORM_CONFIG_DB_USER must differ from APP_DB_USER." >&2
    exit 1
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$PLATFORM_CONFIG_DB_USER') THEN
            CREATE ROLE "$PLATFORM_CONFIG_DB_USER" LOGIN PASSWORD '$PLATFORM_CONFIG_DB_PASSWORD'
                NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
        END IF;
    END
    \$\$;
EOSQL
