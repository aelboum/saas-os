#!/usr/bin/env bash
# The host side of scripts/deploy-staging.sh (docs/STAGING.md). It is sent
# over SSH and run inside the staging checkout of the reference production
# stack (docker-compose.prod.yml); it is never run against production.
#
#   staging-remote.sh deploy   <dir> <full commit sha> [first]
#   staging-remote.sh rollback <dir>
#   staging-remote.sh verify   <dir>
#
# Refuses before it changes anything unless:
# - <dir>/STAGING exists (the operator's marker that this host is staging);
# - .env and .env.app exist, are regular files and are not readable by group
#   or others (mode 600 or 400). Their contents are never read or printed.
#
# deploy: fetch, check the commit is a first-parent commit of origin/main,
# check out exactly that commit (detached), validate the Compose file, back
# up the database (skipped only for the first deployment, which has none),
# build, migrate to head with the migration role, start and wait for every
# healthcheck. The deployed and the previous commit are kept in
# <dir>/.deploy-state.
#
# rollback: check out the previous commit, build and start it, wait for the
# healthchecks. It never downgrades the database: migrations are
# expand/contract (docs/DEPLOYMENT-ARCHITECTURE.md section 6), so the
# previous code runs on the newer schema.
#
# verify: print the state and wait for every healthcheck.
set -euo pipefail

COMPOSE_FILE="docker-compose.prod.yml"
WAIT_SECONDS="${STAGING_WAIT_SECONDS:-300}"

die() {
    echo "staging: refused: $*" >&2
    exit 1
}

step() {
    echo "staging: $*"
}

compose() {
    docker compose -f "$COMPOSE_FILE" "$@"
}

preflight() {
    [ -d "$DIR" ] || die "$DIR is not a directory"
    cd "$DIR"
    [ -f STAGING ] || die "$DIR/STAGING is missing: this host is not marked as staging"
    for file in .env .env.app; do
        [ -f "$file" ] && [ ! -L "$file" ] || die "$DIR/$file is missing or not a regular file"
        mode="$(stat -c %a "$file")"
        case "$mode" in
            600 | 400) ;;
            *) die "$DIR/$file has mode $mode; it must be 600 or 400" ;;
        esac
    done
}

read_state() {
    CURRENT=""
    PREVIOUS=""
    if [ -f .deploy-state ]; then
        CURRENT="$(sed -n 's/^current=\([0-9a-f]\{40\}\)$/\1/p' .deploy-state)"
        PREVIOUS="$(sed -n 's/^previous=\([0-9a-f]\{40\}\)$/\1/p' .deploy-state)"
    fi
}

write_state() {
    printf 'current=%s\nprevious=%s\n' "$1" "$2" > .deploy-state.tmp
    mv .deploy-state.tmp .deploy-state
}

start_and_wait() {
    step "build"
    compose build
    if [ "${1:-}" = "migrate" ]; then
        step "migrate to head (the migration role, MIGRATIONS_DATABASE_URL)"
        compose run --rm --no-deps --entrypoint saas-os-migrate backend upgrade head
    fi
    step "start and wait for every healthcheck (${WAIT_SECONDS}s)"
    compose up -d --wait --wait-timeout "$WAIT_SECONDS"
}

deploy() {
    commit="$1"
    first="${2:-}"
    case "$commit" in
        *[!0-9a-f]* | "") die "the commit must be a full 40-character SHA" ;;
    esac
    [ "${#commit}" -eq 40 ] || die "the commit must be a full 40-character SHA"
    preflight
    read_state
    if [ "$first" = "first" ]; then
        [ -z "$CURRENT" ] || die "first deployment asked, but $DIR/.deploy-state names $CURRENT"
    else
        [ -n "$CURRENT" ] || die "no .deploy-state: run the first deployment with --first-deploy"
    fi

    step "fetch origin"
    git fetch --quiet --tags origin
    git rev-list --first-parent origin/main | grep -qx "$commit" \
        || die "$commit is not a first-parent commit of origin/main"
    step "check out $commit"
    git -c advice.detachedHead=false checkout --quiet --detach "$commit"
    [ "$(git rev-parse HEAD)" = "$commit" ] || die "HEAD is not $commit after checkout"
    [ -z "$(git status --porcelain --untracked-files=no)" ] || die "the checkout has local changes"

    step "validate $COMPOSE_FILE"
    compose config --quiet

    if [ "$first" = "first" ]; then
        step "backup skipped: first deployment, no database yet"
    else
        step "back up the database before migrating (saas-os-backup.service)"
        systemctl start --wait saas-os-backup.service
    fi

    start_and_wait migrate
    write_state "$commit" "$CURRENT"
    step "deployed $commit (previous: ${CURRENT:-none})"
}

rollback() {
    preflight
    read_state
    [ -n "$PREVIOUS" ] || die "no previous deployment recorded in $DIR/.deploy-state"
    step "roll back from $CURRENT to $PREVIOUS (the database is not downgraded)"
    git -c advice.detachedHead=false checkout --quiet --detach "$PREVIOUS"
    [ "$(git rev-parse HEAD)" = "$PREVIOUS" ] || die "HEAD is not $PREVIOUS after checkout"
    compose config --quiet
    start_and_wait
    write_state "$PREVIOUS" "$CURRENT"
    step "rolled back to $PREVIOUS (previous: $CURRENT)"
}

verify() {
    preflight
    read_state
    [ -n "$CURRENT" ] || die "nothing deployed: $DIR/.deploy-state is missing"
    [ "$(git rev-parse HEAD)" = "$CURRENT" ] || die "HEAD is not the deployed commit $CURRENT"
    step "deployed $CURRENT (previous: ${PREVIOUS:-none})"
    compose up -d --wait --wait-timeout "$WAIT_SECONDS" --no-recreate
    compose ps
}

command="${1:-}"
DIR="${2:-}"
[ -n "$DIR" ] || die "usage: staging-remote.sh deploy|rollback|verify <dir> [...]"
case "$command" in
    deploy) deploy "${3:-}" "${4:-}" ;;
    rollback) rollback ;;
    verify) verify ;;
    *) die "unknown command '$command'" ;;
esac
