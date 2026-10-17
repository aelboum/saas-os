"""Who may reach the platform-configuration connection
(docs/ADR/0056-platform-configuration-database-identity.md D3).

An AST scan of every module under `saas_os/`:

- only `saas_os.core.platform_authority.transactions` imports the privileged
  session (`platform_config_session_scope`);
- the API and the worker import only the startup guard;
- nothing imports the module itself, or any other name from it, and no
  public package re-exports it;
- the operations that use it are exactly the three AI configuration writes.
"""

from __future__ import annotations

import ast
from pathlib import Path

import saas_os
from saas_os.core.platform_authority.operations import (
    AI_ENDPOINT_TRUST_CONFIGURE,
    AI_POLICY_CONFIGURE,
    AI_PROVIDER_CONFIGURE,
    PLATFORM_CONFIGURATION_OPERATIONS,
)

_MODULE = "saas_os.infra.db.platform_config"
_ROOT = Path(saas_os.__file__).parent

# module path relative to saas_os/ -> the names it may import from _MODULE
_APPROVED: dict[str, frozenset[str]] = {
    "core/platform_authority/transactions.py": frozenset({"platform_config_session_scope"}),
    "api/platform.py": frozenset({"assert_no_platform_config_credential"}),
    "api/worker.py": frozenset(
        {"assert_no_platform_config_credential", "PlatformConfigCredentialExposedError"}
    ),
}


def _imports() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in _ROOT.rglob("*.py"):
        relative = path.relative_to(_ROOT).as_posix()
        if relative == "infra/db/platform_config.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module == _MODULE:
                    found.setdefault(relative, set()).update(a.name for a in node.names)
                elif node.module == "saas_os.infra.db" and any(
                    a.name == "platform_config" for a in node.names
                ):
                    found.setdefault(relative, set()).add("<module>")
            elif isinstance(node, ast.Import):
                if any(a.name == _MODULE for a in node.names):
                    found.setdefault(relative, set()).add("<module>")
    return found


def test_only_the_approved_modules_reach_the_platform_configuration_connection() -> None:
    found = _imports()
    assert set(found) <= set(_APPROVED), sorted(set(found) - set(_APPROVED))
    for module, names in found.items():
        assert names <= _APPROVED[module], (module, sorted(names - _APPROVED[module]))
    assert "platform_config_session_scope" in found.get(
        "core/platform_authority/transactions.py", set()
    )


def test_no_public_package_exports_it() -> None:
    import saas_os.core.platform_authority as platform_authority
    import saas_os.inference as inference
    import saas_os.infra.db as infra_db

    for package in (infra_db, platform_authority, inference):
        exported = set(getattr(package, "__all__", ())) | {
            name for name in vars(package) if not name.startswith("_")
        }
        assert not exported & {
            "platform_config_session_scope",
            "get_platform_config_engine",
            "get_platform_config_session_factory",
        }, package.__name__
    assert "platform_config" not in set(getattr(infra_db, "__all__", ()))


def test_the_privileged_operations_are_exactly_the_ai_configuration_writes() -> None:
    assert PLATFORM_CONFIGURATION_OPERATIONS == frozenset(
        {AI_PROVIDER_CONFIGURE, AI_ENDPOINT_TRUST_CONFIGURE, AI_POLICY_CONFIGURE}
    )
