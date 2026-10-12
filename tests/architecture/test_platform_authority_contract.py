"""Platform-authority architecture contract (ADR-0045 Phase B) -- static,
hermetic.

Pins the boundaries the design depends on, as properties of this
repository's source:

- platform storage is touched by one package, and platform audit rows are
  constructed in one function;
- every platform operation takes its caller explicitly;
- `SystemCaller`/`SystemAuthority` are imported only by reviewed modules,
  and by no HTTP module;
- Phase B ships no HTTP surface and none of the Phase C operations.

**What this is not.** These are static checks on this repository's own
code. They authenticate nothing at run time: any in-process code can
construct a `SystemCaller`, and a consuming product's code is not scanned.
A purpose is a label, not a credential. The run-time checks are
`authorize_platform_caller()` and the declared operation table; these
tests keep that boundary from eroding unnoticed.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import saas_os.core.platform_authority as platform_authority
from saas_os.core.platform_authority import PLATFORM_OPERATIONS

_REPO = Path(__file__).resolve().parents[2]
_SAAS_OS = _REPO / "saas_os"
_PACKAGE = _SAAS_OS / "core" / "platform_authority"
_MODELS = {"PlatformOperator", "PlatformGrant", "PlatformAuditLogEntry"}


def _sources() -> list[Path]:
    return [
        path
        for path in sorted(_SAAS_OS.rglob("*.py"))
        if "__pycache__" not in path.parts and "migrations" not in path.parts
    ]


def _rel(path: Path) -> str:
    return path.relative_to(_REPO).as_posix()


def _imported_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


def _imported_modules(tree: ast.AST) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
    return modules


# --- storage and evidence have one owner ------------------------------------


def test_only_the_platform_authority_package_touches_the_platform_models() -> None:
    offenders = []
    for path in _sources():
        if _PACKAGE in path.parents:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _imported_names(tree) & _MODELS or any(
            module.startswith("saas_os.core.platform_authority.models")
            for module in _imported_modules(tree)
        ):
            offenders.append(_rel(path))
    assert offenders == []


def test_platform_audit_rows_are_constructed_only_by_the_audit_module() -> None:
    """Evidence is only as trustworthy as the set of functions that write
    it. In this repository that set is one module."""
    constructors = []
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == (
                "PlatformAuditLogEntry"
            ):
                constructors.append(_rel(path))
    assert set(constructors) == {"saas_os/core/platform_authority/audit.py"}


def test_the_package_never_deletes_and_never_runs_raw_sql() -> None:
    """Rows are revoked, never deleted; and Core has no raw-SQL escape."""
    for path in sorted(_PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = _imported_names(tree)
        assert "delete" not in names, _rel(path)
        assert "text" not in names, _rel(path)
        assert not any(m.split(".")[0] == "sqlalchemy" for m in _imported_modules(tree)), path


def test_tenant_rbac_source_never_mentions_platform_authority() -> None:
    """`can()` reads no platform operator or grant. The import-linter
    contract proves there is no import path; this proves there is no
    mention at all."""
    for path in sorted((_SAAS_OS / "core" / "rbac").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert "platform_authority" not in source, _rel(path)
        assert "platform_can" not in source, _rel(path)


def test_the_package_never_consults_the_platform_tenant_or_tenant_rbac() -> None:
    """`PLATFORM_TENANT_ID` grants nothing: no code here reads it, and no
    tenant authorization function is called."""
    forbidden = {"get_platform_tenant_id", "require_platform_tenant", "can", "authorize_caller"}
    for path in sorted(_PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert not _imported_names(tree) & forbidden, _rel(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                callee = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                assert callee not in forbidden, (_rel(path), callee)


# --- explicit callers ----------------------------------------------------------

_OPERATIONS = (
    "enroll_operator",
    "suspend_operator",
    "reactivate_operator",
    "revoke_operator",
    "grant_platform_permission",
    "revoke_platform_permission",
    "bootstrap_platform_owner",
    "recover_platform_authority",
)


def test_every_platform_operation_takes_a_required_keyword_only_caller_and_reason() -> None:
    for name in _OPERATIONS:
        signature = inspect.signature(getattr(platform_authority, name))
        for parameter_name in ("caller", "reason"):
            parameter = signature.parameters[parameter_name]
            assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, (name, parameter_name)
            assert parameter.default is inspect.Parameter.empty, (name, parameter_name)


def test_authorize_platform_caller_cannot_be_given_a_set_of_accepted_purposes() -> None:
    """The accepted purposes come from the declared table. A call site
    names an operation and nothing else -- it cannot widen the set, which
    `saas_os.core.rbac.authorize_caller(system_authorities=...)` allows."""
    parameters = inspect.signature(platform_authority.authorize_platform_caller).parameters
    assert set(parameters) == {"caller", "session", "operation"}
    assert parameters["session"].default is inspect.Parameter.empty  # no standalone form
    assert "system_authorities" not in parameters


def test_implemented_operations_are_exactly_the_authority_rows_of_the_table() -> None:
    """Phase B implements the six operator and grant operations. Every
    other row of the table is a declaration for a later phase."""
    from saas_os.core.platform_authority import operations

    implemented = {
        operations.OPERATOR_ENROLL,
        operations.OPERATOR_SUSPEND,
        operations.OPERATOR_REACTIVATE,
        operations.OPERATOR_REVOKE,
        operations.GRANT_CREATE,
        operations.GRANT_REVOKE,
    }
    assert implemented == {
        key
        for key, row in PLATFORM_OPERATIONS.items()
        if key.split(".")[0] in ("operator", "grant")
    } - {"operator.read"}
    used: set[str] = set()
    for path in sorted(_PACKAGE.glob("*.py")):
        if path.name == "operations.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        used |= _imported_names(tree) & {
            "OPERATOR_ENROLL",
            "OPERATOR_SUSPEND",
            "OPERATOR_REACTIVATE",
            "OPERATOR_REVOKE",
            "GRANT_CREATE",
            "GRANT_REVOKE",
        }
    assert len(used) == 6


# --- no HTTP surface, no Phase C behaviour ------------------------------------------


def test_no_http_module_imports_platform_authority_except_the_bootstrap_command() -> None:
    importers = []
    for path in sorted((_SAAS_OS / "api").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if any(m.startswith("saas_os.core.platform_authority") for m in _imported_modules(tree)):
            importers.append(_rel(path))
    assert importers == ["saas_os/api/platform_bootstrap.py"]


def test_phase_b_ships_no_platform_router_and_no_platform_route() -> None:
    assert not (_SAAS_OS / "api" / "platform_admin").exists()
    for path in sorted((_SAAS_OS / "api").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        assert "/v1/platform" not in source, _rel(path)
        assert "require_platform_permission" not in source, _rel(path)
        assert "build_platform_admin_router" not in source, _rel(path)
        assert "PLATFORM_ADMIN_HTTP_ENABLED" not in source, _rel(path)


def test_the_bootstrap_command_is_not_a_router() -> None:
    tree = ast.parse((_SAAS_OS / "api" / "platform_bootstrap.py").read_text(encoding="utf-8"))
    modules = _imported_modules(tree)
    assert not any(m.split(".")[0] in ("fastapi", "starlette") for m in modules)
    assert not any(m.startswith("saas_os.api") for m in modules)  # imports no route module


def test_no_phase_c_operation_exists() -> None:
    """ADR-0045's gate: `deactivate_user` and `reactivate_user` are neither
    defined nor exported until their PostgreSQL race tests pass. Phase B
    also adds no session or API-key revocation, no oversight read and no
    tenant-lifecycle caller."""
    gated = {
        "deactivate_user",
        "reactivate_user",
        "revoke_user_sessions",
        "revoke_user_api_keys",
        "commercial_overview",
    }
    defined = []
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name in gated:
                defined.append((_rel(path), node.name))
    assert defined == []
    assert not gated & set(platform_authority.__all__)
