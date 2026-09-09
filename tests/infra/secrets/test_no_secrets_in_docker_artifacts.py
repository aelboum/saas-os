"""Static build-artifact inspection (docs/IMPLEMENTATION-ROADMAP.md Phase
2.3 section 11: "a build-artifact inspection test confirming no secret
value appears in a built Docker image layer").

This is a static check of the committed Dockerfile/`.dockerignore`/
`docker-compose.yml` -- it does not build an image or inspect actual
layers (that would need a running Docker daemon, like
`scripts/check-docker.sh`, and is out of this phase's scope). It proves
the *source* of a potential leak is absent: no `ENV`/`ARG` default or
`COPY` of an env file could bake a secret into the image, and the build
context excludes `.env` before Docker ever sees it -- consistent with
Phase 1.4's own empirical verification of the same `.dockerignore` rules.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_dockerfile_never_sets_a_real_env_or_arg_default_for_a_known_secret_name() -> None:
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    known_secret_names = ("DATABASE_URL", "POSTGRES_PASSWORD", "ZITADEL_CLIENT_SECRET")
    for name in known_secret_names:
        assert not re.search(rf"^\s*(ENV|ARG)\s+{name}=", dockerfile, re.MULTILINE), (
            f"Dockerfile must not set a default value for {name} via ENV/ARG "
            "(docs/ADR/0012-secrets-management.md)"
        )


def test_dockerfile_never_copies_an_env_file() -> None:
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert not re.search(r"^\s*COPY\s+.*\.env\b", dockerfile, re.MULTILINE), (
        "Dockerfile must never COPY a .env file into the image "
        "(docs/ADR/0012-secrets-management.md)"
    )


def test_dockerignore_excludes_env_files_from_the_build_context() -> None:
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    lines = {line.strip() for line in dockerignore.splitlines()}
    assert ".env" in lines
    assert ".env.*" in lines


def test_compose_file_never_hardcodes_a_secret_value() -> None:
    """A committed `docker-compose.yml` may name *where* a secret comes
    from (an env var, `env_file: .env`) but never a literal value
    (docs/ADR/0012-secrets-management.md).
    """
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    known_secret_names = ("POSTGRES_PASSWORD", "POSTGRES_USER")
    for name in known_secret_names:
        # Only the `${VAR}` indirection form is permitted for these keys --
        # a literal value directly after the key would be a hardcoded secret.
        for match in re.finditer(rf"^\s*{name}:\s*(.+)$", compose, re.MULTILINE):
            value = match.group(1).strip()
            assert value.startswith("${") and value.endswith("}"), (
                f"docker-compose.yml must reference {name} via ${{...}} indirection, "
                f"found a literal value instead: {value!r}"
            )
