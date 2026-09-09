"""Architecture-boundary tests for docs/ARCHITECTURE.md section 2.

These tests enforce the platform's core dependency rule:

    Products         -> SaaS Core -> Infrastructure
    AI Control Plane -> SaaS Core -> Infrastructure

They must fail if a developer later introduces a forbidden import. See
docs/ADR/0001-layered-architecture-and-dependency-rule.md and
docs/ADR/0011-backend-language-and-toolchain.md (import-linter is the
accepted boundary-enforcement mechanism for the Python backend).

Every rule here is enforced by exactly one mechanism -- the import-linter
contracts declared in pyproject.toml `[tool.importlinter]` -- and these
tests are thin wrappers around `lint-imports`'s report, not a second,
parallel enforcement path. (An earlier version of this file additionally
hand-parsed core/'s AST for forbidden AI/LLM imports; that was replaced in
Phase 1.3 by a third import-linter contract using
`include_external_packages = true`, which catches the same violations
through the same tool the internal-boundary rules already use -- see
docs/IMPLEMENTATION-ROADMAP.md Phase 1.3.)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_import_linter() -> subprocess.CompletedProcess[str]:
    # import-linter ships a `lint-imports` console script but has no
    # `python -m importlinter` entrypoint, so invoke the script installed
    # alongside the current interpreter directly.
    script = Path(sys.executable).with_name(
        "lint-imports.exe" if sys.platform == "win32" else "lint-imports"
    )
    return subprocess.run(
        [str(script)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def test_import_linter_contracts_all_pass() -> None:
    """All import-linter contracts declared in pyproject.toml must pass.

    This is the single source of truth for every forbidden-dependency rule;
    the report is also parsed below so each contract has its own assertion
    and failure message.
    """
    result = _run_import_linter()
    assert result.returncode == 0, (
        f"import-linter reported a boundary violation:\n{result.stdout}\n{result.stderr}"
    )


def test_core_cannot_import_products_or_control_plane() -> None:
    result = _run_import_linter()
    assert "Core does not depend on Products or the AI Control Plane KEPT" in result.stdout


def test_infra_cannot_import_products_or_control_plane() -> None:
    result = _run_import_linter()
    assert (
        "Infrastructure does not depend on Products or the AI Control Plane KEPT" in result.stdout
    )


def test_control_plane_can_depend_on_core() -> None:
    """Positive check: the allowed direction actually resolves."""
    import control_plane
    import core

    assert control_plane.CORE_MARKER == core.CORE_MARKER == "core"


def test_products_can_depend_on_core() -> None:
    """Positive check: the allowed direction actually resolves."""
    import products

    import core

    assert products.CORE_MARKER == core.CORE_MARKER == "core"


def test_core_has_no_ai_or_llm_framework_dependency() -> None:
    """`core` must remain deterministic and functional with the AI Control
    Plane completely disabled (docs/ARCHITECTURE.md section 2, rule 5/6):
    no AI/LLM/agent framework may be imported by any module under core/.
    """
    result = _run_import_linter()
    assert "Core does not depend on AI or LLM frameworks KEPT" in result.stdout


def test_only_infra_db_can_import_sqlalchemy_or_psycopg() -> None:
    """docs/MULTI-TENANCY.md section 3: infra/db is the single database-
    access chokepoint -- core, products, and control_plane must not be
    able to reach SQLAlchemy or psycopg directly (docs/IMPLEMENTATION-
    ROADMAP.md Phase 2.1 chokepoint audit).
    """
    result = _run_import_linter()
    assert "Only infra/db may import SQLAlchemy or psycopg directly KEPT" in result.stdout


def test_core_can_depend_on_infra_db_without_a_direct_sqlalchemy_edge() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 3.1: `core/tenancy` is the
    first Core module with a real runtime dependency on `infra.db`
    (session_scope, the shared ORM base). Because the "Only infra/db may
    import SQLAlchemy or psycopg directly" contract is reachability-based,
    this dependency could only be added safely alongside the `ignore_imports`
    entries in `pyproject.toml` for infra/db's own internal use of
    sqlalchemy (verified empirically while implementing this phase: before
    those entries existed, merely adding `from infra.db import
    session_scope` to `core/__init__.py` broke this contract even though
    `core` never imports `sqlalchemy` itself). This test proves the fix
    holds for the real, shipped dependency, not just a throwaway one.
    """
    import core.tenancy  # noqa: F401 -- the import itself is what's tested

    result = _run_import_linter()
    assert result.returncode == 0, (
        f"core.tenancy's real infra.db dependency broke import-linter:\n{result.stdout}"
    )
    assert "Only infra/db may import SQLAlchemy or psycopg directly KEPT" in result.stdout


def test_forbidden_direct_sqlalchemy_import_from_core_is_still_caught() -> None:
    """Non-vacuous proof that the `ignore_imports` entries added for
    core/tenancy's legitimate infra.db dependency (see the test above and
    pyproject.toml) only exempt that specific internal path -- a real,
    direct `import sqlalchemy` written straight into Core must still be
    caught, exactly as before those entries existed.
    """
    target = REPO_ROOT / "core" / "__init__.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\nimport sqlalchemy\n")
        result = _run_import_linter()
        assert result.returncode != 0, (
            "expected lint-imports to catch a direct `import sqlalchemy` in core/, "
            f"but it reported success:\n{result.stdout}"
        )
        assert "core is not allowed to import sqlalchemy" in result.stdout
        assert "Only infra/db may import SQLAlchemy or psycopg directly BROKEN" in result.stdout
    finally:
        target.write_bytes(original)

    clean_result = _run_import_linter()
    assert clean_result.returncode == 0, (
        f"core/__init__.py was not fully restored after the test:\n{clean_result.stdout}"
    )


def test_infra_cannot_import_core() -> None:
    """docs/ARCHITECTURE.md section 2: the dependency rule is one-directional
    (Product -> Core -> Infra) -- Infra must not import Core, even though
    Core is free to import Infra (docs/IMPLEMENTATION-ROADMAP.md Phase 2.2).
    """
    result = _run_import_linter()
    assert "Infrastructure does not depend on Core KEPT" in result.stdout


def test_infra_has_no_ai_or_llm_framework_dependency() -> None:
    """Mirrors test_core_has_no_ai_or_llm_framework_dependency for infra/
    (docs/ARCHITECTURE.md section 2, rule 5; docs/IMPLEMENTATION-ROADMAP.md
    Phase 2.2): infra/observability must remain usable with the AI Control
    Plane completely disabled.
    """
    result = _run_import_linter()
    assert "Infrastructure does not depend on AI or LLM frameworks KEPT" in result.stdout


def test_only_infra_secrets_can_import_its_own_provider_implementations() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 2.3: consumers (including other
    infra/ subpackages, per ADR-0012's binding rule that no module outside
    infra/secrets ever depends on a concrete secrets-provider implementation
    directly) must reach secrets only through infra.secrets's public
    SecretsProvider interface, not infra.secrets.providers.
    """
    result = _run_import_linter()
    assert (
        "Only infra/secrets may import its own concrete provider implementations KEPT"
        in result.stdout
    )


def test_forbidden_provider_implementation_import_is_actually_caught() -> None:
    """Non-vacuous proof (same discipline as
    test_forbidden_database_import_is_actually_caught): a real forbidden
    `import infra.secrets.providers` is temporarily written into a real,
    tracked infra/db module (a listed source_module of the contract),
    `lint-imports` is run against it, and the violation is asserted --
    then the file is restored, with a follow-up clean run confirming the
    repository is left exactly as it was.
    """
    target = REPO_ROOT / "infra" / "db" / "__init__.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\nimport infra.secrets.providers\n")
        result = _run_import_linter()
        assert result.returncode != 0, (
            "expected lint-imports to catch a forbidden "
            "`import infra.secrets.providers` in infra/db/, but it reported "
            f"success:\n{result.stdout}"
        )
        assert (
            "Only infra/secrets may import its own concrete provider "
            "implementations BROKEN" in result.stdout
        )
    finally:
        target.write_bytes(original)

    clean_result = _run_import_linter()
    assert clean_result.returncode == 0, (
        f"infra/db/__init__.py was not fully restored after the test:\n{clean_result.stdout}"
    )


def test_forbidden_infra_to_core_import_is_actually_caught() -> None:
    """Non-vacuous proof (same discipline as
    test_forbidden_database_import_is_actually_caught): a real forbidden
    `import core` is temporarily written into a real, tracked infra/
    module, `lint-imports` is run against it, and the violation is
    asserted -- then the file is restored, with a follow-up clean run
    confirming the repository is left exactly as it was.
    """
    target = REPO_ROOT / "infra" / "__init__.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\nimport core\n")
        result = _run_import_linter()
        assert result.returncode != 0, (
            "expected lint-imports to catch a forbidden `import core` in infra/, "
            f"but it reported success:\n{result.stdout}"
        )
        assert "infra is not allowed to import core" in result.stdout
        assert "Infrastructure does not depend on Core BROKEN" in result.stdout
    finally:
        target.write_bytes(original)

    clean_result = _run_import_linter()
    assert clean_result.returncode == 0, (
        f"infra/__init__.py was not fully restored after the test:\n{clean_result.stdout}"
    )


def test_orchestration_can_depend_on_data_authorization() -> None:
    """Positive check: P1.1's wiring direction (orchestration ->
    data_authorization) actually resolves -- `control_plane.orchestration
    .service` imports `control_plane.data_authorization`'s public
    `DataAuthorizationDecision`/`DataAuthorizationOutcome` types.
    """
    from control_plane.data_authorization import DataAuthorizationOutcome
    from control_plane.orchestration.service import DataAuthorizationDecision

    assert DataAuthorizationDecision is not None
    assert DataAuthorizationOutcome.ALLOW.value == "allow"


def test_data_authorization_does_not_depend_on_tool_authorization_or_approvals() -> None:
    """P1.1: Tool Authorization and Data Authorization must remain
    independent, one-directional gates (docs/AI-CONTROL-PLANE.md section
    2.1) -- `control_plane.data_authorization` must never import back into
    `control_plane.orchestration` or `control_plane.approvals`.
    """
    result = _run_import_linter()
    assert (
        "Data Authorization does not depend on Tool Authorization or Approvals KEPT"
        in result.stdout
    )


def test_data_authorization_has_no_ai_or_llm_framework_dependency() -> None:
    """P1.1: the module that decides whether data may cross the
    external-provider boundary must never itself reach for an AI/LLM SDK
    directly (docs/IMPLEMENTATION-ROADMAP.md Phase 9.2's own Scope).
    """
    result = _run_import_linter()
    assert "Data Authorization does not depend on AI or LLM frameworks KEPT" in result.stdout


def test_forbidden_data_authorization_to_orchestration_import_is_actually_caught() -> None:
    """Non-vacuous proof (same discipline as
    test_forbidden_database_import_is_actually_caught): a real forbidden
    `import control_plane.orchestration` is temporarily written into a
    real, tracked `control_plane/data_authorization/` module,
    `lint-imports` is run against it, and the violation is asserted --
    then the file is restored, with a follow-up clean run confirming the
    repository is left exactly as it was.
    """
    target = REPO_ROOT / "control-plane" / "control_plane" / "data_authorization" / "__init__.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\nimport control_plane.orchestration\n")
        result = _run_import_linter()
        assert result.returncode != 0, (
            "expected lint-imports to catch a forbidden "
            "`import control_plane.orchestration` in control_plane/data_authorization/, "
            f"but it reported success:\n{result.stdout}"
        )
        assert (
            "Data Authorization does not depend on Tool Authorization or Approvals BROKEN"
            in result.stdout
        )
    finally:
        target.write_bytes(original)

    clean_result = _run_import_linter()
    assert clean_result.returncode == 0, (
        "control_plane/data_authorization/__init__.py was not fully restored after the "
        f"test:\n{clean_result.stdout}"
    )


def test_backup_restore_is_not_reachable_from_core_products_control_plane_or_api() -> None:
    """P1.3: `infra.db.backup` (pg_dump/pg_restore/database-creation
    tooling) must never become an application-runtime capability
    (`infra/db/backup.py`'s own Security Boundary docstring).
    """
    result = _run_import_linter()
    assert "Backup/restore is not an application-runtime capability KEPT" in result.stdout


def test_forbidden_backup_import_from_core_is_actually_caught() -> None:
    """Non-vacuous proof (same discipline as
    test_forbidden_database_import_is_actually_caught): a real forbidden
    `import infra.db.backup` is temporarily written into a real, tracked
    `core/__init__.py`, `lint-imports` is run against it, and the
    violation is asserted -- then the file is restored, with a follow-up
    clean run confirming the repository is left exactly as it was.
    """
    target = REPO_ROOT / "core" / "__init__.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\nimport infra.db.backup\n")
        result = _run_import_linter()
        assert result.returncode != 0, (
            "expected lint-imports to catch a forbidden `import infra.db.backup` in core/, "
            f"but it reported success:\n{result.stdout}"
        )
        assert "Backup/restore is not an application-runtime capability BROKEN" in result.stdout
    finally:
        target.write_bytes(original)

    clean_result = _run_import_linter()
    assert clean_result.returncode == 0, (
        f"core/__init__.py was not fully restored after the test:\n{clean_result.stdout}"
    )


def test_forbidden_database_import_is_actually_caught() -> None:
    """Non-vacuous proof that the chokepoint contract *works*, not merely
    that today's source happens to be clean (the failure mode this test
    exists to rule out -- docs/IMPLEMENTATION-ROADMAP.md Phase 2.1
    chokepoint audit). A real forbidden import is temporarily written into
    a real, tracked module, `lint-imports` is run against it, and the
    violation is asserted -- then the file is restored, with a follow-up
    clean run confirming the repository is left exactly as it was.

    This mutates `core/__init__.py` on disk for the duration of this test
    only; the `finally` block guarantees it is restored even if an
    assertion above it fails. Read/write is byte-exact (`read_bytes`/
    `write_bytes`, not `read_text`/`write_text`) so restoration doesn't
    silently normalize the file's original line endings into a spurious
    diff -- found empirically while writing this test.
    """
    target = REPO_ROOT / "core" / "__init__.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\nimport psycopg\n")
        result = _run_import_linter()
        assert result.returncode != 0, (
            "expected lint-imports to catch a forbidden `import psycopg` in core/, "
            f"but it reported success:\n{result.stdout}"
        )
        assert "core is not allowed to import psycopg" in result.stdout
        assert "Only infra/db may import SQLAlchemy or psycopg directly BROKEN" in result.stdout
    finally:
        target.write_bytes(original)

    clean_result = _run_import_linter()
    assert clean_result.returncode == 0, (
        f"core/__init__.py was not fully restored after the test:\n{clean_result.stdout}"
    )
