"""Who may reach the migrations-role transaction and the ledger deletion
(owner decision B of 2026-11-02; ADR-0045 amendment of 2026-11-02).

An AST scan of every module under `saas_os/`:

- only `saas_os.core.permission_grants.expiry` imports
  `saas_os.infra.db.migrations_role`, and only its session scope;
- only the operator procedure `saas_os.ops.permission_grant_ledger_expiry`
  imports the deletion (`saas_os.core.permission_grants.expiry`): no purge
  step, job, route, product or other Core module reaches it;
- no public package re-exports either, so `import saas_os.<package>`
  never offers them.

Hermetic: no database.
"""

from __future__ import annotations

import ast
from pathlib import Path

import saas_os

_ROOT = Path(saas_os.__file__).parent
_ROLE_MODULE = "saas_os.infra.db.migrations_role"
_EXPIRY_MODULE = "saas_os.core.permission_grants.expiry"


def _importers(module: str, own_path: str) -> dict[str, set[str]]:
    package, _, leaf = module.rpartition(".")
    found: dict[str, set[str]] = {}
    for path in _ROOT.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(_ROOT).as_posix()
        if relative == own_path:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module == module:
                    found.setdefault(relative, set()).update(a.name for a in node.names)
                elif node.module == package and any(a.name == leaf for a in node.names):
                    found.setdefault(relative, set()).add("<module>")
            elif isinstance(node, ast.Import) and any(a.name == module for a in node.names):
                found.setdefault(relative, set()).add("<module>")
    return found


def test_only_the_deletion_opens_the_migrations_role_transaction() -> None:
    assert _importers(_ROLE_MODULE, "infra/db/migrations_role.py") == {
        "core/permission_grants/expiry.py": {"migrations_role_session_scope"},
    }


def test_only_the_operator_procedure_reaches_the_deletion() -> None:
    found = _importers(_EXPIRY_MODULE, "core/permission_grants/expiry.py")
    assert set(found) == {"ops/permission_grant_ledger_expiry.py"}, sorted(found)


def test_no_purge_code_mentions_the_deletion() -> None:
    """The deletion is never part of an automatic tenant purge."""
    for path in sorted((_ROOT / "core" / "tenancy").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        for name in ("expire_permission_grant_ledger_rows", "migrations_role"):
            assert name not in source, (path.name, name)


def test_no_public_package_exports_them() -> None:
    import saas_os.core.permission_grants as grants
    import saas_os.infra.db as infra_db

    for package in (grants, infra_db):
        exported = set(getattr(package, "__all__", ()))
        assert not exported & {
            "expire_permission_grant_ledger_rows",
            "migrations_role_session_scope",
            "validate_migrations_role",
        }, package.__name__
