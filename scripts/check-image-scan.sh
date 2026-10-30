#!/usr/bin/env bash
# Image scan and SBOM for the two images this repository builds
# (docs/SECURITY.md, "Image scan and SBOM").
#
#   bash scripts/check-image-scan.sh            # build both images, then scan
#   BACKEND_TAG=... FRONTEND_TAG=... SKIP_BUILD=1 bash scripts/check-image-scan.sh
#
# Fails when Trivy reports a HIGH or CRITICAL vulnerability that has a fixed
# version, in the OS packages or the language packages of either image.
# Unfixed findings are not failed on: nothing in this repository can remove
# them. Writes a CycloneDX SBOM per image to $SBOM_DIR (default build/sbom).
# Trivy runs from its own image, pinned by digest, against the local Docker
# daemon; it downloads only its vulnerability database.
set -euo pipefail
cd "$(dirname "$0")/.."

TRIVY_IMAGE="aquasec/trivy:0.69.3@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c"
BACKEND_TAG="${BACKEND_TAG:-saas-os-scan-backend:local}"
FRONTEND_TAG="${FRONTEND_TAG:-saas-os-scan-frontend:local}"
SBOM_DIR="${SBOM_DIR:-build/sbom}"
CACHE_VOLUME="${TRIVY_CACHE_VOLUME:-saas-os-trivy-cache}"

if [ -z "${SKIP_BUILD:-}" ]; then
    echo "== docker build: backend =="
    docker build -q -t "$BACKEND_TAG" . >/dev/null
    echo "== docker build: frontend =="
    docker build -q -t "$FRONTEND_TAG" ./frontend >/dev/null
fi

mkdir -p "$SBOM_DIR"
SBOM_ABS="$(cd "$SBOM_DIR" && pwd)"

trivy() {
    MSYS_NO_PATHCONV=1 docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$CACHE_VOLUME:/root/.cache" \
        -v "$SBOM_ABS:/sbom" \
        "$TRIVY_IMAGE" "$@"
}

status=0
for pair in "backend=$BACKEND_TAG" "frontend=$FRONTEND_TAG"; do
    name="${pair%%=*}"
    image="${pair#*=}"
    echo "== SBOM: $name =="
    trivy image --quiet --format cyclonedx --output "/sbom/$name.cdx.json" "$image"
    echo "wrote $SBOM_DIR/$name.cdx.json"
    echo "== scan: $name (HIGH, CRITICAL, fixed versions only) =="
    if ! trivy image --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed \
            --exit-code 1 --format table "$image"; then
        echo "FAIL: $name has a HIGH or CRITICAL vulnerability with a fixed version"
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    exit 1
fi
echo "PASS: no fixable HIGH or CRITICAL vulnerability in either image"
