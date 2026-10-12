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
    contract proves no module of `saas_os.core.rbac` imports the package
    directly (an indirect path is permitted, ADR-0045 section 5); this
    proves there is no mention at all."""
    for path in sorted((_SAAS_OS / "core" / "rbac").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert "platform_authority" not in source, _rel(path)
        assert "platform_can" not in source, _rel(path)


# --- who may import the package ------------------------------------------------

_PLATFORM_PACKAGE = "saas_os.core.platform_authority"

# Every module outside the package that imports it, with the reason. The
# import-linter contract forbids only a direct import from `saas_os.core.rbac`
# (indirect paths are permitted), so this list is what keeps a new dependency
# on platform authority a reviewed change: adding an importer means adding an
# entry here. No module of `saas_os.core.rbac` may ever be added.
_APPROVED_DIRECT_IMPORTERS = {
    "saas_os/api/platform_bootstrap.py": "the owner bootstrap and recovery command",
}


def _platform_package_imports(tree: ast.AST) -> bool:
    """Whether `tree` imports the platform-authority package in any form:
    `import`, `from ... import`, at module scope or deferred inside a
    function, or by a literal name passed to `import_module`/`__import__`."""
    parent, _, leaf = _PLATFORM_PACKAGE.rpartition(".")

    def names_package(module: str) -> bool:
        return module == _PLATFORM_PACKAGE or module.startswith(_PLATFORM_PACKAGE + ".")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(names_package(alias.name) for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                # A relative import: only modules of `saas_os.core` can name
                # the package this way (`from . import platform_authority`,
                # `from .platform_authority import ...`).
                if module.split(".")[0] == leaf or any(a.name == leaf for a in node.names):
                    return True
            elif names_package(module):
                return True
            elif module == parent and any(alias.name == leaf for alias in node.names):
                return True
        elif isinstance(node, ast.Call):
            callee = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if callee in ("import_module", "__import__") and any(
                isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and names_package(arg.value)
                for arg in node.args
            ):
                return True
    return False


def _direct_importers(root: Path) -> set[str]:
    package = root / "saas_os" / "core" / "platform_authority"
    importers = set()
    for path in sorted((root / "saas_os").rglob("*.py")):
        if "__pycache__" in path.parts or package in path.parents:
            continue
        if _platform_package_imports(ast.parse(path.read_text(encoding="utf-8"))):
            importers.add(path.relative_to(root).as_posix())
    return importers


def test_only_approved_modules_import_platform_authority_directly() -> None:
    unapproved = sorted(_direct_importers(_REPO) - set(_APPROVED_DIRECT_IMPORTERS))
    assert unapproved == [], (
        "unreviewed direct importer(s) of saas_os.core.platform_authority; each needs a "
        f"reviewed entry in _APPROVED_DIRECT_IMPORTERS: {unapproved}"
    )


def test_approved_direct_importers_has_no_stale_entries() -> None:
    stale = sorted(set(_APPROVED_DIRECT_IMPORTERS) - _direct_importers(_REPO))
    assert stale == [], f"approved importer(s) no longer import the package: {stale}"


def test_every_approved_direct_importer_has_a_justification() -> None:
    for path, reason in _APPROVED_DIRECT_IMPORTERS.items():
        assert reason.strip(), path


def test_tenant_rbac_is_never_an_approved_direct_importer() -> None:
    """The allowlist cannot be used to let tenant RBAC in: the direct
    prohibition is unconditional."""
    assert not any(path.startswith("saas_os/core/rbac/") for path in _APPROVED_DIRECT_IMPORTERS)


def test_direct_importer_scan_detects_every_import_form(tmp_path: Path) -> None:
    """Non-vacuousness: the real scanner finds each way of importing the
    package in a synthetic tree, including a deferred import, and ignores
    the package's own modules and a module that only mentions the name."""
    forms = {
        "saas_os/core/tenancy/service.py": (
            "def create_tenant():\n"
            "    from saas_os.core.platform_authority import authorize_platform_caller\n"
        ),
        "saas_os/core/rbac/authorization.py": "import saas_os.core.platform_authority\n",
        "saas_os/core/identity/service.py": (
            "from saas_os.core.platform_authority.audit import record_platform_refusal\n"
        ),
        "saas_os/core/feature_flags/service.py": "from saas_os.core import platform_authority\n",
        "saas_os/core/api_keys/service.py": "from ..platform_authority import platform_can\n",
        "saas_os/core/usage.py": "from . import platform_authority\n",
        "saas_os/api/main.py": (
            "import importlib\n\n"
            "importlib.import_module('saas_os.core.platform_authority.service')\n"
        ),
        "saas_os/core/platform_authority/service.py": (
            "from saas_os.core.platform_authority.audit import validate_reason\n"
        ),
        "saas_os/infra/db/rls.py": "# owned by saas_os.core.platform_authority\n",
        "saas_os/core/billing/service.py": "from saas_os.core.platform_authority_x import y\n",
    }
    for relative, source in forms.items():
        module = tmp_path / relative
        module.parent.mkdir(parents=True, exist_ok=True)
        module.write_text(source, encoding="utf-8")
    assert _direct_importers(tmp_path) == {
        "saas_os/core/tenancy/service.py",
        "saas_os/core/rbac/authorization.py",
        "saas_os/core/identity/service.py",
        "saas_os/core/feature_flags/service.py",
        "saas_os/core/api_keys/service.py",
        "saas_os/core/usage.py",
        "saas_os/api/main.py",
    }
    assert not _direct_importers(tmp_path) <= set(_APPROVED_DIRECT_IMPORTERS)


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
