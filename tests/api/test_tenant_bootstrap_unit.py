"""Unit tests for `api.tenant_bootstrap` (post-audit F-02) that need no
database: input validation fails closed, the production confirmation
gate refuses before any provisioning call, the CLI never prints a
database URL, the step order is the documented one (authority last), and
the module stays inside the secrets boundary. Everything that touches
PostgreSQL is in `tests/api/test_tenant_bootstrap_integration.py`."""

from __future__ import annotations

import ast
import inspect
import uuid
from pathlib import Path

import api.tenant_bootstrap as bootstrap_module
import pytest
from api.tenant_bootstrap import (
    FIRST_TENANT_OWNER_PERMISSIONS,
    FIRST_TENANT_OWNER_ROLE_NAME,
    BootstrapInputError,
    BootstrapRequest,
    BootstrapResult,
    main,
    validate_request,
)
from core.config import get_settings

from api.v1 import tenant_status

_ISSUER = "https://issuer.example.test"
_SUBJECT = "424242"
_VALID_ARGS = ["--tenant-name", "Acme", "--owner-issuer", _ISSUER, "--owner-subject", _SUBJECT]


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _fake_result() -> BootstrapResult:
    return BootstrapResult(
        tenant_id=uuid.uuid4(),
        tenant_status="active",
        owner_user_id=uuid.uuid4(),
        membership_id=uuid.uuid4(),
        role_id=uuid.uuid4(),
        role_name=FIRST_TENANT_OWNER_ROLE_NAME,
        permissions=("tenant:read_status",),
        created=("tenant",),
    )


# --- Input validation -----------------------------------------------------------


def test_valid_inputs_are_normalized() -> None:
    request = validate_request("  Acme Ltd  ", _ISSUER + "/", " 424242 ")
    assert request == BootstrapRequest(
        tenant_name="Acme Ltd", owner_issuer=_ISSUER, owner_subject="424242"
    )


@pytest.mark.parametrize(
    ("name", "issuer", "subject", "field"),
    [
        ("", _ISSUER, _SUBJECT, "tenant name"),
        ("   ", _ISSUER, _SUBJECT, "tenant name"),
        ("a" * 256, _ISSUER, _SUBJECT, "tenant name"),
        ("Acme\x00Ltd", _ISSUER, _SUBJECT, "tenant name"),
        ("Acme\nLtd", _ISSUER, _SUBJECT, "tenant name"),
        ("Acme", "", _SUBJECT, "owner issuer"),
        ("Acme", "issuer.example.test", _SUBJECT, "owner issuer"),
        ("Acme", "ftp://issuer.example.test", _SUBJECT, "owner issuer"),
        ("Acme", "https://", _SUBJECT, "owner issuer"),
        ("Acme", "https://issuer.example.test?x=1", _SUBJECT, "owner issuer"),
        ("Acme", "https://issuer.example.test#frag", _SUBJECT, "owner issuer"),
        ("Acme", "https://issuer .example.test", _SUBJECT, "owner issuer"),
        ("Acme", "https://" + "a" * 2050, _SUBJECT, "owner issuer"),
        ("Acme", _ISSUER, "", "owner subject"),
        ("Acme", _ISSUER, "   ", "owner subject"),
        ("Acme", _ISSUER, "42 42", "owner subject"),
        ("Acme", _ISSUER, "s" * 256, "owner subject"),
        ("Acme", _ISSUER, "42\x07", "owner subject"),
    ],
)
def test_invalid_inputs_fail_closed_naming_only_the_field(
    name: str, issuer: str, subject: str, field: str
) -> None:
    with pytest.raises(BootstrapInputError) as excinfo:
        validate_request(name, issuer, subject)
    message = str(excinfo.value)
    assert field in message
    # Never echoes the offending value back (it could be anything an
    # operator pasted by mistake).
    for value in (name, issuer, subject):
        # Only values long enough to be recognisably "the input" (a bare
        # scheme such as `https://` also appears in the generic help text).
        if len(value.strip()) >= 12:
            assert value not in message


def test_non_string_inputs_are_rejected() -> None:
    with pytest.raises(BootstrapInputError):
        validate_request(None, _ISSUER, _SUBJECT)  # type: ignore[arg-type]
    with pytest.raises(BootstrapInputError):
        validate_request("Acme", _ISSUER, 424242)  # type: ignore[arg-type]


# --- Least-privilege contract is tied to the real routes ----------------------


def test_owner_permissions_are_exactly_the_external_api_permissions() -> None:
    """The drift guard: the literal tuple in the bootstrap module must equal
    the `require_permission(RESOURCE, ACTION)` pairs the routes declare."""
    assert FIRST_TENANT_OWNER_PERMISSIONS == ((tenant_status.RESOURCE, tenant_status.ACTION),)
    assert FIRST_TENANT_OWNER_ROLE_NAME == "owner"
    for resource, _action in FIRST_TENANT_OWNER_PERMISSIONS:
        assert not resource.startswith("control_plane"), "no AI Control Plane authority"


def test_bootstrap_module_does_not_import_the_route_graph() -> None:
    """`--help`, input validation, and the production gate must work
    without queue configuration: importing `api.v1` would register Core
    job handlers, which resolve `REDIS_URL` at import time."""
    tree = ast.parse(inspect.getsource(bootstrap_module))
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert not any(module.startswith("api.v1") for module in imported)
    assert not any(module.startswith("core.usage") for module in imported)


# --- Production confirmation gate (before any provisioning call) --------------


def _install_spies(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    calls = {"bootstrap": 0, "assess": 0}

    def fake_bootstrap(request: BootstrapRequest) -> BootstrapResult:
        calls["bootstrap"] += 1
        return _fake_result()

    def fake_assess(request: BootstrapRequest):
        calls["assess"] += 1
        return bootstrap_module.BootstrapPlan(
            request=request,
            matching_tenants=0,
            tenant_id=None,
            tenant_status=None,
            tenant_member_count=None,
            owner_identity_known=False,
            owner_already_member=False,
            would_create=("tenant",),
        )

    monkeypatch.setattr(bootstrap_module, "bootstrap_first_tenant", fake_bootstrap)
    monkeypatch.setattr(bootstrap_module, "assess_bootstrap", fake_assess)
    return calls


def test_production_without_confirmation_is_refused_before_any_provisioning(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    calls = _install_spies(monkeypatch)
    assert main(_VALID_ARGS) == 2
    assert calls == {"bootstrap": 0, "assess": 0}
    assert "--confirm-production" in capsys.readouterr().err


def test_production_with_confirmation_runs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    calls = _install_spies(monkeypatch)
    assert main([*_VALID_ARGS, "--confirm-production"]) == 0
    assert calls["bootstrap"] == 1
    assert "first-tenant bootstrap: OK" in capsys.readouterr().out


def test_production_dry_run_needs_no_confirmation_and_never_provisions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    calls = _install_spies(monkeypatch)
    assert main([*_VALID_ARGS, "--dry-run"]) == 0
    assert calls == {"bootstrap": 0, "assess": 1}
    assert "DRY RUN -- nothing was changed." in capsys.readouterr().out


@pytest.mark.parametrize("environment", ["development", "test"])
def test_non_production_runs_without_confirmation(
    monkeypatch: pytest.MonkeyPatch, environment: str
) -> None:
    monkeypatch.setenv("ENVIRONMENT", environment)
    calls = _install_spies(monkeypatch)
    assert main(_VALID_ARGS) == 0
    assert calls["bootstrap"] == 1


def test_invalid_input_is_a_usage_error_before_any_provisioning(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = _install_spies(monkeypatch)
    assert main(["--tenant-name", "   ", "--owner-issuer", _ISSUER, "--owner-subject", "1"]) == 2
    assert calls == {"bootstrap": 0, "assess": 0}
    assert "invalid input" in capsys.readouterr().err


def test_unknown_arguments_are_a_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_spies(monkeypatch)
    assert main([*_VALID_ARGS, "--password", "x"]) == 2
    assert calls == {"bootstrap": 0, "assess": 0}


def test_cli_never_accepts_a_credential_argument() -> None:
    parser = bootstrap_module._build_parser()
    option_strings = {opt for action in parser._actions for opt in action.option_strings}
    for forbidden in ("--password", "--token", "--access-token", "--client-secret", "--secret"):
        assert forbidden not in option_strings


# --- Failure output: type name only, never a DSN ---------------------------------


def test_unexpected_failure_prints_only_the_exception_type(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def exploding(request: BootstrapRequest) -> BootstrapResult:
        # Synthetic DSN-shaped message (a driver error could look like this);
        # the test proves it is never echoed. Not a credential.
        # pragma: allowlist nextline secret
        raise RuntimeError("connection failed for postgresql://saas_os_app:hunter2@db:5432/x")

    monkeypatch.setattr(bootstrap_module, "bootstrap_first_tenant", exploding)
    assert main(_VALID_ARGS) == 1
    captured = capsys.readouterr()
    assert "RuntimeError" in captured.err
    assert "hunter2" not in captured.err + captured.out
    assert "postgresql://" not in captured.err + captured.out


def test_refused_bootstrap_prints_the_safe_reason(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refusing(request: BootstrapRequest) -> BootstrapResult:
        raise bootstrap_module.BootstrapConflictError("already exists -- refusing.")

    monkeypatch.setattr(bootstrap_module, "bootstrap_first_tenant", refusing)
    assert main(_VALID_ARGS) == 1
    assert "bootstrap refused: already exists" in capsys.readouterr().err


# --- Step order: authority is the last mutation ------------------------------------


def test_provisioning_order_grants_authority_last(monkeypatch: pytest.MonkeyPatch) -> None:
    """With every Core service replaced by a recorder, the bootstrap
    performs the documented sequence and `assign_role` (the only
    authority-conferring mutation) is the final mutation before the
    `can()` verification."""
    order: list[str] = []
    tenant_id, user_id, role_id, membership_id, permission_id = (uuid.uuid4() for _ in range(5))

    class _Tenant:
        id = tenant_id
        name = "Acme"
        status = "pending"

    class _ActiveTenant(_Tenant):
        status = "active"

    class _User:
        id = user_id

    class _Role:
        id = role_id
        name = FIRST_TENANT_OWNER_ROLE_NAME

    class _Permission:
        id = permission_id

    class _Membership:
        id = membership_id

    def rec(name: str, value: object = None):
        def _f(*args: object, **kwargs: object) -> object:
            order.append(name)
            return value

        return _f

    monkeypatch.setattr(bootstrap_module, "validate_application_role", rec("role_guard"))
    monkeypatch.setattr(bootstrap_module, "get_engine", lambda: object())
    monkeypatch.setattr(bootstrap_module, "find_tenants_by_name", rec("find_tenants", []))
    monkeypatch.setattr(bootstrap_module, "create_tenant", rec("create_tenant", _Tenant()))
    monkeypatch.setattr(
        bootstrap_module, "transition_tenant_status", rec("activate", _ActiveTenant())
    )
    monkeypatch.setattr(bootstrap_module, "find_external_identity", rec("find_identity", None))
    monkeypatch.setattr(
        bootstrap_module, "get_or_create_user_for_external_identity", rec("ensure_user", _User())
    )
    monkeypatch.setattr(bootstrap_module, "list_roles", rec("list_roles", []))
    monkeypatch.setattr(bootstrap_module, "create_role", rec("create_role", _Role()))
    monkeypatch.setattr(
        bootstrap_module, "register_permission", rec("register_permission", _Permission())
    )
    monkeypatch.setattr(bootstrap_module, "get_role_permission", rec("get_grant", None))
    monkeypatch.setattr(bootstrap_module, "grant_permission", rec("grant_permission"))
    monkeypatch.setattr(bootstrap_module, "get_membership", rec("get_membership", None))
    monkeypatch.setattr(
        bootstrap_module, "add_tenant_membership", rec("add_membership", _Membership())
    )
    monkeypatch.setattr(bootstrap_module, "get_membership_role", rec("get_assignment", None))
    monkeypatch.setattr(bootstrap_module, "assign_role", rec("assign_role"))
    monkeypatch.setattr(bootstrap_module, "can", rec("can", True))
    monkeypatch.setattr(bootstrap_module, "record_audit_event", rec("audit"))

    result = bootstrap_module.bootstrap_first_tenant(
        BootstrapRequest(tenant_name="Acme", owner_issuer=_ISSUER, owner_subject=_SUBJECT)
    )

    mutations = [
        step
        for step in order
        if step
        in {
            "create_tenant",
            "activate",
            "ensure_user",
            "create_role",
            "grant_permission",
            "add_membership",
            "assign_role",
        }
    ]
    assert mutations == [
        "create_tenant",
        "activate",
        "ensure_user",
        "create_role",
        "grant_permission",
        "add_membership",
        "assign_role",
    ]
    assert order[0] == "role_guard", "the RLS role guard runs before anything else"
    assert order.index("assign_role") < order.index("can"), "verification follows authority"
    assert order[-1] == "can"
    assert result.created == (
        "tenant",
        "activation",
        "owner_user",
        "owner_role",
        "grant:tenant:read_status",
        "owner_membership",
        "role_assignment",
    )


def test_failed_verification_is_a_failure_not_a_success(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    monkeypatch.setattr(bootstrap_module, "validate_application_role", lambda engine: None)
    monkeypatch.setattr(bootstrap_module, "get_engine", lambda: object())

    class _T:
        id = uuid.uuid4()
        status = "active"

    class _U:
        id = uuid.uuid4()

    class _R:
        id = uuid.uuid4()
        name = FIRST_TENANT_OWNER_ROLE_NAME

    class _M:
        id = uuid.uuid4()
        user_id = _U.id

    monkeypatch.setattr(bootstrap_module, "find_tenants_by_name", lambda name: [_T()])
    monkeypatch.setattr(bootstrap_module, "list_tenant_members", lambda tenant_id: [])
    monkeypatch.setattr(bootstrap_module, "find_external_identity", lambda i, s: None)
    monkeypatch.setattr(
        bootstrap_module, "get_or_create_user_for_external_identity", lambda i, s: _U()
    )
    monkeypatch.setattr(bootstrap_module, "list_roles", lambda tenant_id: [_R()])
    monkeypatch.setattr(bootstrap_module, "register_permission", lambda r, a: _R())
    monkeypatch.setattr(bootstrap_module, "get_role_permission", lambda t, r, p: object())
    monkeypatch.setattr(bootstrap_module, "get_membership", lambda t, u: _M())
    monkeypatch.setattr(bootstrap_module, "get_membership_role", lambda t, m, r: object())
    monkeypatch.setattr(bootstrap_module, "can", lambda **kwargs: order.append("can") or False)
    with pytest.raises(bootstrap_module.BootstrapVerificationError):
        bootstrap_module.bootstrap_first_tenant(
            BootstrapRequest(tenant_name="Acme", owner_issuer=_ISSUER, owner_subject=_SUBJECT)
        )
    assert order == ["can"]


# --- Secrets boundary -----------------------------------------------------------------


def test_module_never_reads_the_environment_or_secret_providers_directly() -> None:
    """The bootstrap needs no secret of its own: the database URL reaches
    it only through `infra.db` (which resolves it via the SecretsProvider),
    and `ENVIRONMENT` only through `core.config.get_settings()`. Nothing
    here touches `os.environ`/`os.getenv` or the concrete providers."""
    source = inspect.getsource(bootstrap_module)
    tree = ast.parse(source)
    attribute_accesses = {
        f"{node.value.id}.{node.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
    }
    assert "os.environ" not in attribute_accesses
    assert "os.getenv" not in attribute_accesses
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert "infra.secrets.providers" not in imported
    assert "infra.secrets" not in imported
    assert not any(
        isinstance(node, ast.Import) and any(alias.name == "os" for alias in node.names)
        for node in ast.walk(tree)
    )
    assert Path(bootstrap_module.__file__).name == "tenant_bootstrap.py"
