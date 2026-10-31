"""The image scan runs in CI on the images it built and cannot be weakened
silently (`docs/SECURITY.md`, "Image scan and SBOM")."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (REPO_ROOT / "scripts" / "check-image-scan.sh").read_text(encoding="utf-8")
CI = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


def test_trivy_is_pinned_by_digest() -> None:
    assert re.search(r'TRIVY_IMAGE="aquasec/trivy:[0-9.]+@sha256:[0-9a-f]{64}"', SCRIPT)


def test_the_scan_fails_on_fixable_high_and_critical_findings() -> None:
    assert "--severity HIGH,CRITICAL" in SCRIPT
    assert "--exit-code 1" in SCRIPT
    assert "--format cyclonedx" in SCRIPT


def test_ci_scans_the_images_check_docker_built() -> None:
    docker_job = CI[CI.index("name: docker build + runtime validation") :]
    docker_job = docker_job[: docker_job.index("\n  packaging:")]
    assert docker_job.index("bash scripts/check-docker.sh") < docker_job.index(
        "bash scripts/check-image-scan.sh"
    )
    assert "BACKEND_TAG: saas-os-backend:check" in docker_job
    assert "FRONTEND_TAG: saas-os-frontend:check" in docker_job
    assert 'SKIP_BUILD: "1"' in docker_job
    check_docker = (REPO_ROOT / "scripts" / "check-docker.sh").read_text(encoding="utf-8")
    assert 'BACKEND_TAG="saas-os-backend:check"' in check_docker
    assert 'FRONTEND_TAG="saas-os-frontend:check"' in check_docker


def test_ci_runs_the_tls_production_validation_in_a_required_job() -> None:
    """`docker build + runtime validation` is one of the seven checks the
    `main` ruleset requires, so the TLS production validation gates every
    merge (docs/PRODUCTION-READINESS.md, gates 5 and 12)."""
    docker_job = CI[CI.index("name: docker build + runtime validation") :]
    docker_job = docker_job[: docker_job.index("\n  packaging:")]
    assert "run: bash scripts/check-docker-prod-tls.sh" in docker_job


def test_ci_runs_the_single_origin_runtime_check_in_a_required_job() -> None:
    """ADR-0024's runtime check runs in the same required job, so the edge
    routing of the development topology gates every merge."""
    docker_job = CI[CI.index("name: docker build + runtime validation") :]
    docker_job = docker_job[: docker_job.index("\n  packaging:")]
    assert "run: bash scripts/check-single-origin.sh" in docker_job
