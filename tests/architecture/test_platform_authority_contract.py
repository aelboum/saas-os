"""Platform-authority architecture contract (ADR-0045 Phase B) -- static,
hermetic.

Pins the boundaries the design depends on, as properties of this
repository's source:

- platform storage is touched by one package, and platform audit rows are
  constructed in one function;
- every platform operation takes its caller explicitly;
- `SystemCaller`/`SystemAuthority` are imported only by reviewed modules,
  and by no HTTP module;
- no HTTP surface exists for platform operations (Phase D), and each
  Phase C operation lives in the Core module that owns its state.

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
    "saas_os/api/platform.py": "startup validation of the oversight statement-timeout setting",
    # ADR-0045 Phase D: the opt-in HTTP surface. The chain refuses earlier;
    # the router names the caller to Core, which decides.
    "saas_os/api/dependencies.py": "the platform_permission route policy chain (section 7)",
    "saas_os/api/platform_admin/router.py": "the opt-in platform-admin routes",
    "saas_os/api/v1/tenant_suspension.py": "opt-in self-service suspension: Core refusal types",
    # ADR-0045 Phase C: the Core modules that own the state authorize
    # through the platform chokepoint and write platform evidence.
    "saas_os/core/tenancy/authority.py": "authorization and evidence for the tenant lifecycle",
    "saas_os/core/tenancy/service.py": "lifecycle refusal types and operation keys",
    "saas_os/core/tenancy/registry.py": "oversight read of the tenant registry",
    "saas_os/core/feature_flags/service.py": "flag definition and tenant overrides",
    "saas_os/core/identity/user_authority.py": "deactivation, credential revocation, erasure guard",
    "saas_os/core/identity/sessions.py": "the operator-login audit event at session issuance",
    "saas_os/core/billing/oversight.py": "the commercial overview",
    "saas_os/core/outbox/replay.py": "operator replay of dead-lettered outbox events",
    # ADR-0053: the audit digests read platform evidence (read-only) through
    # `platform_authority.digest_source`; they never touch the models.
    "saas_os/core/audit_digest/service.py": "audit digests: read-only platform evidence",
    # ADR-0054 AI-C: the AI configuration operations run through
    # `run_platform_change` / `run_oversight_read`; the Control Plane never
    # opens the platform transaction or writes platform evidence itself.
    "saas_os/control_plane/inference/config/service.py": "AI configuration platform operations",
    "saas_os/control_plane/inference/usage.py": "AI usage totals: one tenant, aggregates only",
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


def test_http_modules_import_from_platform_authority_only_what_was_reviewed() -> None:
    """Every module under `saas_os/api` that imports the package, and
    exactly the names it imports, judged on the import statements
    themselves: no `import ... as`, no submodule, no name that is not
    listed. A new name here is a reviewed change.

    What matters most is what is *absent*: no HTTP module imports
    `authorize_platform_caller`, a system purpose, the bootstrap or
    recovery composites (other than the command), or a platform model."""
    package = "saas_os.core.platform_authority"
    expected: dict[str, set[str]] = {
        "saas_os/api/platform.py": {"get_oversight_read_config", "get_platform_mutation_config"},
        "saas_os/api/dependencies.py": {
            "PlatformOperationTimeoutError",
            "PlatformPermission",
            "is_active_platform_operator",
            "platform_can",
            "platform_operation",
            "record_platform_refusal",
        },
        "saas_os/api/v1/tenant_suspension.py": {
            "InvalidPlatformRequestError",
            "PlatformNotAuthorizedError",
            "PlatformOperationTimeoutError",
        },
        "saas_os/api/platform_admin/router.py": {
            # errors it translates
            "DuplicatePlatformGrantError",
            "InactivePlatformSubjectError",
            "InvalidPlatformOperatorStateError",
            "InvalidPlatformRequestError",
            "OversightReadTimeoutError",
            "PlatformGrantNotFoundError",
            "PlatformOperationTimeoutError",
            "PlatformNotAuthorizedError",
            "PlatformOperatorAlreadyEnrolledError",
            "PlatformOperatorNotFoundError",
            "PlatformRefusalError",
            "PlatformSubjectNotFoundError",
            "UserNotResolvedError",
            # the permission vocabulary
            "PlatformPermission",
            # the operations and reads it routes
            "enroll_operator",
            "grant_platform_permission",
            "list_platform_audit",
            "list_platform_grants",
            "list_platform_operators",
            "reactivate_operator",
            "revoke_operator",
            "revoke_platform_permission",
            "suspend_operator",
        },
    }
    found: dict[str, set[str]] = {}
    for path in sorted((_SAAS_OS / "api").rglob("*.py")):
        if "__pycache__" in path.parts or path.name == "platform_bootstrap.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                assert not any(alias.name.startswith(package) for alias in node.names), _rel(path)
            elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith(package):
                assert node.module == package, (_rel(path), node.module)  # the root only
                assert all(alias.asname is None for alias in node.names), _rel(path)
                found.setdefault(_rel(path), set()).update(alias.name for alias in node.names)
    assert found == expected
    forbidden = {
        "authorize_platform_caller",
        "bootstrap_platform_owner",
        "recover_platform_authority",
        "PlatformOperator",
        "PlatformGrant",
        "PlatformAuditLogEntry",
        "record_platform_event_in_transaction",
        "lock_platform_owners",
    }
    assert not forbidden & set().union(*found.values())


def test_the_platform_admin_surface_is_confined_to_its_package() -> None:
    """Phase D. The `/v1/platform` prefix and the router builder exist in
    `saas_os/api/platform_admin/` and nowhere else under `saas_os/api`;
    `require_platform_permission` is declared in `dependencies.py` and used
    only by the router; and the enabling setting is read by the
    configuration module only."""
    package = _SAAS_OS / "api" / "platform_admin"
    assert (package / "router.py").exists() and (package / "config.py").exists()
    for path in sorted((_SAAS_OS / "api").rglob("*.py")):
        if "__pycache__" in path.parts or package in path.parents:
            continue
        source = path.read_text(encoding="utf-8")
        assert "/v1/platform" not in source, _rel(path)
        assert "build_platform_admin_router" not in source, _rel(path)
        # Named in the two modules that enforce it (at startup, and on each
        # request); read from the environment by the configuration module only.
        named = "PLATFORM_ADMIN_HTTP_ENABLED" in source
        assert not named or path.name in ("route_policy.py", "dependencies.py"), _rel(path)
        assert not (named and "os.environ" in source), _rel(path)
        if path.name != "dependencies.py":
            assert "require_platform_permission" not in source or path.name == "route_policy.py", (
                _rel(path)
            )


def test_nothing_in_saas_os_mounts_the_platform_admin_router() -> None:
    """The product's half of the two opt-ins: no module of SaaS OS -- the
    application factory, the reference `main.py`, the consumer scaffold --
    calls the builder or includes the router. Only a product does."""
    for path in sorted(_SAAS_OS.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if (_SAAS_OS / "api" / "platform_admin") in path.parents:
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        assert "build_platform_admin_router" not in source, _rel(path)
        assert "platform_admin" not in source or path.name in (
            "dependencies.py",
            "platform.py",
        ), _rel(path)


def test_the_bootstrap_command_is_not_a_router() -> None:
    tree = ast.parse((_SAAS_OS / "api" / "platform_bootstrap.py").read_text(encoding="utf-8"))
    modules = _imported_modules(tree)
    assert not any(m.split(".")[0] in ("fastapi", "starlette") for m in modules)
    assert not any(m.startswith("saas_os.api") for m in modules)  # imports no route module


_PHASE_C_OPERATIONS = {
    "deactivate_user": "saas_os/core/identity/user_authority.py",
    "reactivate_user": "saas_os/core/identity/user_authority.py",
    "revoke_user_sessions": "saas_os/core/identity/user_authority.py",
    "revoke_user_api_keys": "saas_os/core/identity/user_authority.py",  # pragma: allowlist secret
    "commercial_overview": "saas_os/core/billing/oversight.py",
    "list_tenant_registry": "saas_os/core/tenancy/registry.py",
    "read_tenant_registry_entry": "saas_os/core/tenancy/registry.py",
}


def test_each_phase_c_operation_is_defined_once_in_the_module_that_owns_the_state() -> None:
    """Phase C puts each operation in the Core module that owns the state
    it changes or reads, never in the platform-authority package (which may
    not import those modules) and never twice."""
    defined: dict[str, list[str]] = {}
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                and node.name in _PHASE_C_OPERATIONS
            ):
                defined.setdefault(node.name, []).append(_rel(path))
    assert defined == {name: [path] for name, path in _PHASE_C_OPERATIONS.items()}
    assert not set(_PHASE_C_OPERATIONS) & set(platform_authority.__all__)


def test_every_phase_c_operation_takes_a_required_keyword_only_caller() -> None:
    import saas_os.core.billing.oversight as oversight
    import saas_os.core.feature_flags.service as flags
    import saas_os.core.identity.user_authority as user_authority
    import saas_os.core.tenancy.registry as registry
    import saas_os.core.tenancy.service as tenancy

    operations = [
        tenancy.create_tenant,
        tenancy.move_tenant,
        tenancy.transition_tenant_status,
        flags.create_flag,
        flags.set_tenant_override,
        flags.remove_tenant_override,
        user_authority.deactivate_user,
        user_authority.reactivate_user,
        user_authority.revoke_user_sessions,
        user_authority.revoke_user_api_keys,
        registry.list_tenant_registry,
        registry.read_tenant_registry_entry,
        oversight.commercial_overview,
    ]
    for operation in operations:
        parameter = inspect.signature(operation).parameters["caller"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, operation.__name__
        assert parameter.default is inspect.Parameter.empty, operation.__name__
    for operation in (
        user_authority.deactivate_user,
        user_authority.reactivate_user,
        user_authority.revoke_user_sessions,
        user_authority.revoke_user_api_keys,
    ):
        parameter = inspect.signature(operation).parameters["reason"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, operation.__name__
        assert parameter.default is inspect.Parameter.empty, operation.__name__


# Oversight reads deliberately kept off the network (operator command only).
_OFF_NETWORK_READS = {"read_ai_configuration", "read_ai_usage_totals"}


def test_only_the_platform_admin_router_reaches_a_platform_operation() -> None:
    """Phase D routes the user, credential and oversight operations listed
    in `_PHASE_C_OPERATIONS` and `_OVERSIGHT_READS` from one module, and
    no other HTTP module imports any of them. (The tenant lifecycle and
    flag functions are not in those two lists: `transition_tenant_status`
    is also called by the self-service route, under the tenant chain.)"""
    routed = set(_PHASE_C_OPERATIONS) | (set(_OVERSIGHT_READS) - _OFF_NETWORK_READS)
    router = "saas_os/api/platform_admin/router.py"
    for path in sorted((_SAAS_OS / "api").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        imported = _imported_names(ast.parse(path.read_text(encoding="utf-8")))
        # ADR-0054 AI-C: the AI configuration read has no route at all.
        assert not imported & _OFF_NETWORK_READS, _rel(path)
        names = imported & routed
        if _rel(path) == router:
            assert names == routed, sorted(routed - names)  # every one of them is routed
        else:
            assert names == set(), (_rel(path), names)


# --- Phase D, milestone 1: the remaining oversight reads -----------------------------

_OVERSIGHT_READS = {
    # Reads of the platform's own tables live in the package that owns them.
    "list_platform_operators": "saas_os/core/platform_authority/oversight.py",
    "list_platform_grants": "saas_os/core/platform_authority/oversight.py",
    "list_platform_audit": "saas_os/core/platform_authority/oversight.py",
    # The others, in the Core module that owns the state they read.
    "resolve_user": "saas_os/core/identity/user_authority.py",
    "read_flag_catalog": "saas_os/core/feature_flags/service.py",
    "read_tenant_flag_overrides": "saas_os/core/feature_flags/service.py",
    # ADR-0054 AI-C: the AI configuration is Control Plane state.
    "read_ai_configuration": "saas_os/control_plane/inference/config/service.py",
    "read_ai_usage_totals": "saas_os/control_plane/inference/usage.py",
}


def _oversight_read_definitions() -> dict[str, list[tuple[str, ast.FunctionDef]]]:
    defined: dict[str, list[tuple[str, ast.FunctionDef]]] = {}
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in _OVERSIGHT_READS:
                defined.setdefault(node.name, []).append((_rel(path), node))
    return defined


def test_each_oversight_read_is_defined_once_in_the_module_that_owns_the_state() -> None:
    defined = _oversight_read_definitions()
    assert {name: [path for path, _ in sites] for name, sites in defined.items()} == {
        name: [path] for name, path in _OVERSIGHT_READS.items()
    }


def test_every_oversight_read_runs_through_the_one_audited_path() -> None:
    """Each of these reads calls `run_oversight_read()` -- the attempt row,
    the second authorization, the completion row and both timeouts are
    there and nowhere else -- and never opens a transaction of its own."""
    for name, sites in _oversight_read_definitions().items():
        ((_, function),) = sites
        called = {
            call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", "")
            for call in ast.walk(function)
            if isinstance(call, ast.Call)
        }
        # One tenant's rows: the same path, through its tenant-scope form.
        assert called & {"run_oversight_read", "run_tenant_oversight_read"}, name
        assert not called & {"session_scope", "tenant_session_scope"}, name
        assert not called & {"authorize_platform_caller", "platform_can"}, name


def test_every_oversight_read_takes_a_required_keyword_only_caller() -> None:
    import saas_os.core.feature_flags.service as flags
    import saas_os.core.identity.user_authority as user_authority
    import saas_os.core.platform_authority.oversight as oversight

    for operation in (
        oversight.list_platform_operators,
        oversight.list_platform_grants,
        oversight.list_platform_audit,
        user_authority.resolve_user,
        flags.read_flag_catalog,
        flags.read_tenant_flag_overrides,
    ):
        parameter = inspect.signature(operation).parameters["caller"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, operation.__name__
        assert parameter.default is inspect.Parameter.empty, operation.__name__


def test_every_oversight_operation_of_the_table_has_a_core_read() -> None:
    """The six oversight rows of the operation table (section 4) are all
    implemented: none is a declaration only any more."""
    oversight_rows = {key for key in PLATFORM_OPERATIONS if key.endswith(".read")}
    assert oversight_rows == {
        "tenant.read",
        "user.read",
        "operator.read",
        "audit.read",
        "billing.read",
        "feature_flag.read",
        "ai_config.read",
        "ai_usage.read",
    }
    # Each read names its own operation key, inside its own body.
    expected = {
        "list_platform_operators": "OPERATOR_READ",
        "list_platform_grants": "OPERATOR_READ",
        "list_platform_audit": "AUDIT_READ",
        "resolve_user": "USER_READ",
        "read_flag_catalog": "FEATURE_FLAG_READ",
        "read_tenant_flag_overrides": "FEATURE_FLAG_READ",
        "read_ai_configuration": "AI_CONFIG_READ",
        "read_ai_usage_totals": "AI_USAGE_READ",
    }
    keys = {"TENANT_READ", "USER_READ", "OPERATOR_READ", "AUDIT_READ", "BILLING_READ"}
    keys.update({"FEATURE_FLAG_READ", "AI_CONFIG_READ", "AI_USAGE_READ"})
    for name, sites in _oversight_read_definitions().items():
        ((_, function),) = sites
        named = {node.id for node in ast.walk(function) if isinstance(node, ast.Name)} & keys
        assert named == {expected[name]}, name


def test_no_route_exists_for_what_section_7_keeps_off_the_network() -> None:
    """Moving or deleting a tenant, purging, erasing an identity, the owner
    bootstrap and recovery: no HTTP module imports the function, and the
    router's inventory names no such operation."""
    off_network = {
        "move_tenant",
        "purge_tenant",
        "erase_user_identity",
        "bootstrap_platform_owner",
        "recover_platform_authority",
    }
    for path in sorted((_SAAS_OS / "api").rglob("*.py")):
        if "__pycache__" in path.parts or path.name in (
            "platform_bootstrap.py",
            "tenant_bootstrap.py",
        ):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert not _imported_names(tree) & off_network, _rel(path)
    from saas_os.api.platform_admin.router import PLATFORM_ROUTES

    operations = {route.operation for route in PLATFORM_ROUTES}
    assert not operations & {"tenant.move", "tenant.delete", "tenant.purge_transition"}
    # `TenantStatus.DELETED` is never a target the router asks for.
    router = (_SAAS_OS / "api" / "platform_admin" / "router.py").read_text(encoding="utf-8")
    assert "TenantStatus.DELETED" not in router and "TenantStatus.PURG" not in router
