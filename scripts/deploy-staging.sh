#!/usr/bin/env bash
# Deploys the reference production stack to a staging host (docs/STAGING.md).
# Never production: the host must carry the operator's STAGING marker, and
# every command that touches the host needs --confirm-host naming it again.
#
#   scripts/deploy-staging.sh plan     --host H --dir D --commit SHA [--first-deploy]
#   scripts/deploy-staging.sh deploy   --host H --dir D --commit SHA --confirm-host H [--first-deploy]
#   scripts/deploy-staging.sh rollback --host H --dir D --confirm-host H
#   scripts/deploy-staging.sh verify   --host H --dir D --confirm-host H
#
# `plan` contacts nothing: it checks the arguments and the commit locally and
# prints what `deploy` would do. The other commands run
# deploy/staging-remote.sh on the host over SSH (BatchMode: no password
# prompt, the operator's own key and known_hosts). No secret is read, sent or
# printed by either script; the host's .env and .env.app are created by the
# operator on the host.
set -euo pipefail
cd "$(dirname "$0")/.."

die() {
    echo "deploy-staging: $*" >&2
    exit 2
}

command="${1:-}"
[ -n "$command" ] || die "usage: deploy-staging.sh plan|deploy|rollback|verify --host H --dir D ..."
shift
host=""
dir=""
commit=""
confirm=""
first=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --host) host="${2:-}"; shift 2 ;;
        --dir) dir="${2:-}"; shift 2 ;;
        --commit) commit="${2:-}"; shift 2 ;;
        --confirm-host) confirm="${2:-}"; shift 2 ;;
        --first-deploy) first="first"; shift ;;
        *) die "unknown argument '$1'" ;;
    esac
done

case "$command" in
    plan | deploy | rollback | verify) ;;
    *) die "unknown command '$command'" ;;
esac
[ -n "$host" ] || die "--host is required"
case "$host" in
    -* | *[!A-Za-z0-9@._-]*) die "--host '$host' is not a plain [user@]hostname" ;;
esac
[ -n "$dir" ] || die "--dir is required"
case "$dir" in
    /*) ;;
    *) die "--dir must be an absolute path on the host" ;;
esac
case "$dir" in
    *[!A-Za-z0-9/._-]*) die "--dir '$dir' has characters other than letters, digits, / . _ -" ;;
esac

if [ "$command" = "plan" ] || [ "$command" = "deploy" ]; then
    case "$commit" in
        *[!0-9a-f]* | "") die "--commit must be a full 40-character SHA" ;;
    esac
    [ "${#commit}" -eq 40 ] || die "--commit must be a full 40-character SHA"
    git rev-parse --verify --quiet "$commit^{commit}" >/dev/null \
        || die "$commit is not in this clone; git fetch origin first"
    git rev-list --first-parent origin/main | grep -qx "$commit" \
        || die "$commit is not a first-parent commit of origin/main"
    tag="$(git tag --points-at "$commit" --list 'v*' | head -n 1)"
fi

if [ "$command" = "plan" ]; then
    echo "plan: deploy $commit${tag:+ ($tag)} to $host:$dir"
    [ -n "$tag" ] || echo "plan: note: $commit carries no release tag (a candidate, not a release)"
    echo "plan: on the host, deploy/staging-remote.sh deploy would:"
    echo "  1. refuse unless $dir/STAGING exists and .env, .env.app are mode 600 or 400"
    echo "  2. git fetch; refuse unless $commit is a first-parent commit of origin/main"
    echo "  3. check out $commit detached; refuse on local changes"
    echo "  4. docker compose -f docker-compose.prod.yml config --quiet"
    if [ "$first" = "first" ]; then
        echo "  5. skip the backup (first deployment; refused if .deploy-state exists)"
    else
        echo "  5. systemctl start --wait saas-os-backup.service"
    fi
    echo "  6. build; saas-os-migrate upgrade head; up -d --wait"
    echo "  7. record current/previous in $dir/.deploy-state"
    echo "plan: nothing was contacted or changed"
    exit 0
fi

[ -n "$confirm" ] || die "$command touches $host: repeat it with --confirm-host $host"
[ "$confirm" = "$host" ] || die "--confirm-host '$confirm' does not match --host '$host'"

args=("$command" "$dir")
if [ "$command" = "deploy" ]; then
    args+=("$commit")
    [ -z "$first" ] || args+=("first")
fi
echo "deploy-staging: $command on $host:$dir"
exec ssh -o BatchMode=yes -- "$host" bash -s -- "${args[@]}" < deploy/staging-remote.sh
