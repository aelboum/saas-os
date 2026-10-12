#!/usr/bin/env bash
# Creates the restricted PostgreSQL application runtime role
# (docs/IMPLEMENTATION-ROADMAP.md Phase 3.1 security correction;
# docs/MULTI-TENANCY.md section 2). This is what DATABASE_URL points at --
# Row-Level Security is never applied to a superuser or a BYPASSRLS role,
# with no override, so the application must run as neither.
#
# Runs automatically, once, via the official postgres image's own
# /docker-entrypoint-initdb.d mechanism -- only on first boot of a brand
# new (empty) data volume. Idempotent (IF NOT EXISTS) as defense in depth
# against a manual re-run.
#
# $POSTGRES_USER / $POSTGRES_DB are already in this container's
# environment (the official image's own bootstrap variables).
# $APP_DB_USER / $APP_DB_PASSWORD come from docker-compose's environment,
# themselves sourced from .env (gitignored, never committed --
# docs/ADR/0012-secrets-management.md). This script only ever sees them as
# ephemeral container environment variables -- it does not persist,
# print, or log the password anywhere.

set -euo pipefail

: "${APP_DB_USER:?APP_DB_USER must be set}"
: "${APP_DB_PASSWORD:?APP_DB_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$APP_DB_USER') THEN
            CREATE ROLE "$APP_DB_USER" LOGIN PASSWORD '$APP_DB_PASSWORD'
                NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
        END IF;
    END
    \$\$;

    GRANT CONNECT ON DATABASE "$POSTGRES_DB" TO "$APP_DB_USER";
EOSQL
