"""`python -m saas_os.api.platform_bootstrap` -- hermetic (ADR-0045
section 6, decision D8).

- The bootstrap permission list is an explicit literal: pinned against a
  copy written here, never computed from the vocabulary, and paired with a
  second literal so that every permission is consciously placed.
- A list that does not fit the vocabulary fails before anything is opened.
- Input validation, the production gate and the runtime-role check all
  refuse before Core is called.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path
from typing import Any

import pytest

import saas_os.api.platform_bootstrap as cli
from saas_os.core.authority import SystemAuthority
from saas_os.core.platform_authority import PlatformPermission
from saas_os.infra.db import UnsafeDatabaseRoleError

_REPO = Path(__file__).resolve().parents[2]
_ISSUER = "https://idp.example.test"

# The reviewed bootstrap list (ADR-0045 section 6), in its order.
_REVIEWED_BOOTSTRAP_LIST = (
    "platform.tenant:read",
    "platform.user:read",
    "platform.operator:read",
    "platform.audit:read",
    "platform.billing:read",
    "platform.feature_flag:read",
    "platform.ai_config:read",
    "platform.ai_usage:read",
    "platform.tenant:create",
    "platform.tenant:suspend",
    "platform.tenant:reactivate",
    "platform.tenant:move",
    "platform.tenant:delete",
    "platform.user:deactivate",
    "platform.user:reactivate",
    "platform.session:revoke",
    "platform.api_key:revoke",
    "platform.feature_flag:define",
    "platform.feature_flag:override",
    "platform.ai_provider:manage",
    "platform.ai_endpoint_trust:manage",
    "platform.ai_policy:manage",
    "platform.outbox:replay",
    "platform.authority:manage",
)


# --- the bootstrap list --------------------------------------------------------


def test_bootstrap_list_is_exactly_the_reviewed_literal() -> None:
    assert tuple(p.value for p in cli.BOOTSTRAP_PERMISSIONS) == _REVIEWED_BOOTSTRAP_LIST
    assert cli.NOT_GRANTED_AT_BOOTSTRAP == ()


def test_every_permission_is_placed_in_exactly_one_bootstrap_literal() -> None:
    """Adding a permission to the vocabulary fails here until a reviewer
    places it. It can be neither granted nor left out by omission."""
    granted, withheld = set(cli.BOOTSTRAP_PERMISSIONS), set(cli.NOT_GRANTED_AT_BOOTSTRAP)
    assert not granted & withheld
    assert granted | withheld == set(PlatformPermission)
    assert len(cli.BOOTSTRAP_PERMISSIONS) == len(granted) == 24
    assert cli.validate_bootstrap_list() is cli.BOOTSTRAP_PERMISSIONS


def test_bootstrap_list_is_a_literal_not_derived_from_the_vocabulary() -> None:
    """The assignment in the source is a tuple of explicit attribute
    references -- no call, no comprehension, no starred expression."""
    tree = ast.parse((_REPO / "saas_os/api/platform_bootstrap.py").read_text(encoding="utf-8"))
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") in (
            "BOOTSTRAP_PERMISSIONS",
            "NOT_GRANTED_AT_BOOTSTRAP",
        ):
            assert isinstance(node.value, ast.Tuple), ast.dump(node)
            for element in node.value.elts:
                assert isinstance(element, ast.Attribute), ast.dump(element)
                assert getattr(element.value, "id", None) == "PlatformPermission"
            found = found or node.target.id == "BOOTSTRAP_PERMISSIONS"  # type: ignore[union-attr]
    assert found


@pytest.mark.parametrize(
    ("granted", "withheld", "message"),
    [
        (cli.BOOTSTRAP_PERMISSIONS[:-2] + (PlatformPermission.AUTHORITY_MANAGE,), (), "cover"),
        (cli.BOOTSTRAP_PERMISSIONS + (PlatformPermission.TENANT_READ,), (), "duplicate"),
        (cli.BOOTSTRAP_PERMISSIONS, (PlatformPermission.TENANT_READ,), "both"),
        (cli.BOOTSTRAP_PERMISSIONS[:-1], (PlatformPermission.AUTHORITY_MANAGE,), "must grant"),
        (cli.BOOTSTRAP_PERMISSIONS[:-1] + ("platform.authority:manage",), (), "not a platform"),
        (cli.BOOTSTRAP_PERMISSIONS + ("platform.tenant:purge",), (), "not a platform"),
    ],
)
def test_a_bootstrap_list_that_does_not_fit_the_vocabulary_fails_before_any_write(
    monkeypatch: pytest.MonkeyPatch, granted: Any, withheld: Any, message: str
) -> None:
    """Missing permission, duplicate, listed on both sides, no owner
    permission, a plain string, a value outside the vocabulary: each is
    refused by `validate_bootstrap_list()`, and `bootstrap_owner()` calls
    it before the role check, the identity lookup or Core."""
    monkeypatch.setattr(cli, "BOOTSTRAP_PERMISSIONS", granted)
    monkeypatch.setattr(cli, "NOT_GRANTED_AT_BOOTSTRAP", withheld)
    touched: list[str] = []
    for name in (
        "validate_application_role",
        "get_engine",
        "bootstrap_platform_owner",
    ):
        monkeypatch.setattr(cli, name, lambda *a, _n=name, **k: touched.append(_n))
    with pytest.raises(cli.PlatformBootstrapListError, match=message):
        cli.bootstrap_owner(_ISSUER, "subject", reason="r")
    assert touched == []
    assert (
        cli.main(["bootstrap", "--owner-issuer", _ISSUER, "--owner-subject", "s", "--reason", "r"])
        == 1
    )
    assert touched == []


# --- the purpose it acts with -----------------------------------------------------


def test_the_command_acts_only_with_the_platform_bootstrap_purpose() -> None:
    assert cli._PLATFORM_BOOTSTRAP.authority is SystemAuthority.PLATFORM_BOOTSTRAP
    source = (_REPO / "saas_os/api/platform_bootstrap.py").read_text(encoding="utf-8")
    assert "SystemAuthority.PROVISIONING" not in source
    assert source.count("SystemCaller(") == 1


# --- input validation ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("issuer", "subject"),
    [
        ("", "sub"),
        ("idp.example.test", "sub"),
        ("ftp://idp.example.test", "sub"),
        ("https://idp.example.test?x=1", "sub"),
        ("https://idp.example.test/#frag", "sub"),
        ("https://idp example.test", "sub"),
        (_ISSUER, ""),
        (_ISSUER, "has space"),
        (_ISSUER, "x" * 256),
        (_ISSUER, "ctl\x00"),
    ],
)
def test_invalid_identity_is_refused(issuer: str, subject: str) -> None:
    with pytest.raises(cli.PlatformBootstrapInputError):
        cli.validate_identity(issuer, subject)


def test_issuer_is_normalized_like_the_identity_provider_config() -> None:
    assert cli.validate_identity(_ISSUER + "/", "sub") == (_ISSUER, "sub")


@pytest.mark.parametrize("value", ["*", "platform.*", "all", "platform.tenant:purge", "owner", ""])
def test_grant_must_name_one_permission_from_the_vocabulary(value: str) -> None:
    with pytest.raises(cli.PlatformBootstrapInputError):
        cli.parse_permissions([value])


def test_grant_refuses_a_duplicate_and_accepts_explicit_permissions() -> None:
    with pytest.raises(cli.PlatformBootstrapInputError):
        cli.parse_permissions(["platform.tenant:read", "platform.tenant:read"])
    assert cli.parse_permissions(["platform.authority:manage", "platform.tenant:read"]) == (
        PlatformPermission.AUTHORITY_MANAGE,
        PlatformPermission.TENANT_READ,
    )


def _no_core(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    called: list[str] = []
    monkeypatch.setattr(cli, "bootstrap_owner", lambda *a, **k: called.append("bootstrap"))
    monkeypatch.setattr(cli, "recover", lambda *a, **k: called.append("recover"))
    return called


@pytest.mark.parametrize(
    "argv",
    [
        ["bootstrap", "--owner-issuer", _ISSUER, "--owner-subject", "s"],  # no reason
        ["bootstrap", "--owner-issuer", _ISSUER, "--owner-subject", "s", "--reason", "  "],
        ["bootstrap", "--owner-issuer", "not-a-url", "--owner-subject", "s", "--reason", "r"],
        ["recover", "--reason", "r"],  # nothing to do
        ["recover", "--enroll-issuer", _ISSUER, "--reason", "r"],  # issuer without subject
        [
            "recover",
            "--grant",
            "platform.tenant:read",
            "--suspend-operator",
            str(uuid.uuid4()),
            "--reason",
            "r",
        ],
        ["recover", "--suspend-operator", "not-a-uuid", "--reason", "r"],
        [
            "recover",
            "--enroll-issuer",
            _ISSUER,
            "--enroll-subject",
            "s",
            "--grant",
            "*",
            "--reason",
            "r",
        ],
        ["revoke", "--reason", "r"],  # no such command: recovery never revokes
        ["recover", "--revoke-operator", str(uuid.uuid4()), "--reason", "r"],
        ["recover", "--reactivate-operator", str(uuid.uuid4()), "--reason", "r"],
        [],
    ],
)
def test_usage_errors_exit_2_and_never_reach_core(
    monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    called = _no_core(monkeypatch)
    assert cli.main(argv) == 2
    assert called == []


def test_production_requires_explicit_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    from saas_os.core.config import get_settings

    called = _no_core(monkeypatch)
    monkeypatch.setenv("ENVIRONMENT", "production")
    get_settings.cache_clear()
    try:
        base = ["bootstrap", "--owner-issuer", _ISSUER, "--owner-subject", "s", "--reason", "r"]
        assert cli.main(base) == 2
        suspend = ["recover", "--suspend-operator", str(uuid.uuid4()), "--reason", "r"]
        assert cli.main(suspend) == 2
        assert called == []
        monkeypatch.setattr(cli, "_print_bootstrap", lambda result: None)
        assert cli.main([*base, "--confirm-production"]) == 0
        assert called == ["bootstrap"]
    finally:
        monkeypatch.delenv("ENVIRONMENT")
        get_settings.cache_clear()


def test_a_superuser_or_bypassrls_runtime_role_is_refused_before_core(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unsafe(engine: object) -> None:
        raise UnsafeDatabaseRoleError("role can bypass row-level security")

    reached: list[str] = []
    monkeypatch.setattr(cli, "get_engine", lambda: object())
    monkeypatch.setattr(cli, "validate_application_role", unsafe)
    for name in ("bootstrap_platform_owner", "recover_platform_authority"):
        monkeypatch.setattr(cli, name, lambda *a, _n=name, **k: reached.append(_n))
    argv = ["bootstrap", "--owner-issuer", _ISSUER, "--owner-subject", "s", "--reason", "r"]
    assert cli.main(argv) == 1
    assert cli.main(["recover", "--suspend-operator", str(uuid.uuid4()), "--reason", "r"]) == 1
    assert reached == []


def test_a_database_error_is_reported_by_type_name_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        fake_dsn = "postgresql://user:hunter2@db/saas_os"  # pragma: allowlist secret -- fake
        raise ConnectionError(f"{fake_dsn} unreachable")

    monkeypatch.setattr(cli, "bootstrap_owner", boom)
    argv = ["bootstrap", "--owner-issuer", _ISSUER, "--owner-subject", "s", "--reason", "r"]
    assert cli.main(argv) == 1
    captured = capsys.readouterr()
    assert "ConnectionError" in captured.err
    assert "hunter2" not in captured.err + captured.out


def test_no_module_imports_the_bootstrap_command() -> None:
    """The command is reachable only as a command: nothing in the package
    imports it, so no router can."""
    for path in (_REPO / "saas_os").rglob("*.py"):
        if path.name == "platform_bootstrap.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names = {alias.name for alias in node.names}
                assert "platform_bootstrap" not in (node.module or ""), path
                assert "platform_bootstrap" not in names, path
            elif isinstance(node, ast.Import):
                assert not any("platform_bootstrap" in alias.name for alias in node.names), path


def test_the_command_writes_nothing_itself() -> None:
    """Regression (bootstrap partial write): the command must not create a
    user or an identity link in a transaction of its own before Core has
    decided. It imports no identity write or lookup at all; Core resolves
    the identity inside the platform transaction."""
    tree = ast.parse((_REPO / "saas_os/api/platform_bootstrap.py").read_text(encoding="utf-8"))
    imported: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.add(node.module or "")
            imported.update(alias.name for alias in node.names)
    assert not any(module.startswith("saas_os.core.identity") for module in modules)
    assert not imported & {
        "get_or_create_user_for_external_identity",
        "create_user",
        "link_external_identity",
        "find_external_identity",
        "session_scope",
        "tenant_session_scope",
    }


def test_bootstrap_hands_core_the_identity_not_a_user_id(monkeypatch: pytest.MonkeyPatch) -> None:
    from saas_os.core.platform_authority import OperatorIdentity, PlatformBootstrapResult

    seen: dict[str, Any] = {}
    result = PlatformBootstrapResult(
        operator_id=uuid.uuid4(), user_id=uuid.uuid4(), permissions=(), created=True
    )

    def fake_core(
        owner: Any, permissions: Any, *, caller: Any, reason: str
    ) -> PlatformBootstrapResult:
        seen.update(owner=owner, permissions=permissions, caller=caller, reason=reason)
        return result

    monkeypatch.setattr(cli, "get_engine", lambda: object())
    monkeypatch.setattr(cli, "validate_application_role", lambda engine: None)
    monkeypatch.setattr(cli, "_require_configured_issuer", lambda issuer: None)
    monkeypatch.setattr(cli, "bootstrap_platform_owner", fake_core)
    assert cli.bootstrap_owner(_ISSUER, "subject-1", reason="r") is result
    assert seen["owner"] == OperatorIdentity(_ISSUER, "subject-1")
    assert seen["permissions"] is cli.BOOTSTRAP_PERMISSIONS
    assert seen["caller"].authority is SystemAuthority.PLATFORM_BOOTSTRAP
