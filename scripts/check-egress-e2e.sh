#!/usr/bin/env bash
# ADR-0059 end to end: the worker's egress through the real resolver
# (deploy/egress-dns/unbound.conf plus a test zone) and the real proxy
# (deploy/egress-proxy/squid.conf, unchanged), on isolated Docker networks
# that have no gateway at all -- nothing here can reach a real host.
#
#   networks   saas-os-egress-e2e-internal  internal                  driver, proxy
#              saas-os-egress-e2e-dns       internal, 172.31.53.0/28  driver, resolver (.2)
#              saas-os-egress-e2e-egress    internal, 11.22.33.0/24   proxy, resolver,
#                                                                     destinations (.10, .11)
#
# The driver (scripts/egress_e2e/driver.py) is placed like the worker and
# runs this tree's code (mounted over the image's) in three phases: all up,
# resolver stopped, proxy stopped. scripts/egress_e2e/assertions.py checks
# its outcomes, the destination's connection log and the proxy's access log.
#
# Fixture containers (certificates, the two destinations) run as root to
# write the fixture directory and bind port 443; the driver keeps the
# image's own non-root user.
#
# The image is the backend image (any image with this repository's
# dependencies); set EGRESS_E2E_IMAGE to reuse one, otherwise it is built.
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1  # Git Bash: keep container paths as written

PREFIX=saas-os-egress-e2e
SQUID_IMAGE=ubuntu/squid:6.6-24.04_edge@sha256:8a3baed477e2c282ab8aa5edad442f69873246964f225c5c2ae8364b6610963c
UNBOUND_IMAGE=alpinelinux/unbound:latest@sha256:cd8dcbcaa7b6f223fe154be07f17c13006149be7f56d50c5664f46181e8d5e1b
IMAGE=${EGRESS_E2E_IMAGE:-saas-os-egress-e2e:local}
REPO=$(pwd)
PYTHON=${PYTHON:-python}

remove_resources() {
    for name in driver dest-good dest-wrong resolver proxy; do
        docker rm -f "$PREFIX-$name" >/dev/null 2>&1 || true
    done
    for net in internal dns egress; do
        docker network rm "$PREFIX-$net" >/dev/null 2>&1 || true
    done
}
remove_resources  # anything a previous, interrupted run left behind
WORK=$(mktemp -d)
trap 'remove_resources; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/fixtures" "$WORK/results"
# Docker Desktop on Windows needs native paths for bind mounts; elsewhere
# these are the paths themselves.
host_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf "%s" "$1"; fi; }
MOUNT_REPO=$(host_path "$REPO")
MOUNT_WORK=$(host_path "$WORK")

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "== building $IMAGE =="
    docker build -q -t "$IMAGE" . >/dev/null
fi

echo "== fixtures: throw-away CA and certificates, resolver configuration with the test zone =="
docker run --rm --user 0 -v "$MOUNT_WORK/fixtures:/out" -v "$MOUNT_REPO/scripts/egress_e2e:/e2e:ro" \
    --entrypoint python "$IMAGE" /e2e/make_certs.py /out
cat deploy/egress-dns/unbound.conf scripts/egress_e2e/test-zone.conf >"$WORK/fixtures/unbound.conf"

echo "== isolated networks (no gateway on any of them) =="
docker network create --internal "$PREFIX-internal" >/dev/null
docker network create --internal --subnet 172.31.53.0/28 "$PREFIX-dns" >/dev/null
docker network create --internal --subnet 11.22.33.0/24 "$PREFIX-egress" >/dev/null

echo "== destinations, resolver and proxy =="
for name in good wrong; do
    address=11.22.33.10
    [ "$name" = wrong ] && address=11.22.33.11
    docker run -d --user 0 --name "$PREFIX-dest-$name" --network "$PREFIX-egress" --ip "$address" \
        -v "$MOUNT_WORK/fixtures:/fixtures:ro" -v "$MOUNT_REPO/scripts/egress_e2e:/e2e:ro" \
        --entrypoint python "$IMAGE" -u /e2e/dest_server.py "/fixtures/$name.pem" "/fixtures/$name.key" >/dev/null
done
docker create --name "$PREFIX-resolver" --network "$PREFIX-dns" --ip 172.31.53.2 \
    -v "$MOUNT_WORK/fixtures/unbound.conf:/etc/unbound/unbound.conf:ro" "$UNBOUND_IMAGE" >/dev/null
docker network connect "$PREFIX-egress" "$PREFIX-resolver"
docker start "$PREFIX-resolver" >/dev/null
docker create --name "$PREFIX-proxy" --network "$PREFIX-internal" --network-alias egress-proxy \
    --tmpfs /var/log/squid:uid=13,gid=13 --tmpfs /var/spool/squid:uid=13,gid=13 \
    -v "$MOUNT_REPO/deploy/egress-proxy/squid.conf:/etc/squid/squid.conf:ro" "$SQUID_IMAGE" >/dev/null
docker network connect "$PREFIX-egress" "$PREFIX-proxy"
docker start "$PREFIX-proxy" >/dev/null

wait_for() {  # wait_for <container> <command...>
    local name=$1
    shift
    for _ in $(seq 1 30); do
        if docker exec "$name" "$@" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "FAIL: $name did not become ready"
    docker logs "$name" 2>&1 | tail -20
    return 1
}
wait_for "$PREFIX-resolver" nslookup health.resolver.check 127.0.0.1
wait_for "$PREFIX-proxy" bash -c 'exec 3<>/dev/tcp/127.0.0.1/3128'

docker create --name "$PREFIX-driver" --network "$PREFIX-internal" --dns 172.31.53.2 \
    -e EGRESS_PROXY_URL=http://egress-proxy:3128 -e ENVIRONMENT=test \
    -e REDIS_URL=redis://127.0.0.1:1/0 -e PYTHONPATH=/src \
    -v "$MOUNT_REPO:/src:ro" -v "$MOUNT_WORK/fixtures:/fixtures:ro" -v "$MOUNT_REPO/scripts/egress_e2e:/e2e:ro" \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
docker network connect "$PREFIX-dns" "$PREFIX-driver"
docker start "$PREFIX-driver" >/dev/null

run_phase() {
    echo "== driver: $1 =="
    docker exec "$PREFIX-driver" python /e2e/driver.py "$1" >"$WORK/results/$1.json"
}

run_phase normal
docker logs "$PREFIX-dest-good" 2>/dev/null | grep -c '^connection$' >"$WORK/results/dest-good.count" || true
# The proxy logs to a tmpfs, which a restart empties: copy it now.
docker exec "$PREFIX-proxy" cat /var/log/squid/access.log >"$WORK/results/proxy-access.log"

docker stop "$PREFIX-resolver" >/dev/null
run_phase resolver_down
docker start "$PREFIX-resolver" >/dev/null
wait_for "$PREFIX-resolver" nslookup health.resolver.check 127.0.0.1

docker stop "$PREFIX-proxy" >/dev/null
run_phase proxy_down

docker logs "$PREFIX-dest-good" >"$WORK/results/dest-good.log" 2>&1

echo "== assertions =="
"$PYTHON" scripts/egress_e2e/assertions.py "$MOUNT_WORK/results"
