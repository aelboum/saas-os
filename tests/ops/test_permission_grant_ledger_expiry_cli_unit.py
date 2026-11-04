"""`python -m saas_os.ops.permission_grant_ledger_expiry` (owner decision B
of 2026-11-02): argument guards and the exact Core call. Core is replaced
by a recorder; the procedure against a real database is in
`tests/core/platform_authority/test_permission_grant_ledger_expiry_integration.py`."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from saas_os.core.authority import UserCaller
from saas_os.core.permission_grants.expiry import ExpiredLedgerTenant, LedgerExpiryResult
from saas_os.ops import permission_grant_ledger_expiry as cli

_T = uuid.uuid4()
_T2 = uuid.uuid4()
_OP = uuid.uuid4()
_DIGEST = "cd" * 32
_BASE = ["--operator", str(_OP), "--reason", "TICKET-9: expiry"]


def _result(applied: bool) -> LedgerExpiryResult:
    purged = datetime(2024, 1, 1, tzinfo=UTC)
    return LedgerExpiryResult(
        as_of=datetime(2026, 11, 2, tzinfo=UTC),
        applied=applied,
        eligible=(ExpiredLedgerTenant(_T, 3, purged, datetime(2026, 1, 1, tzinfo=UTC)),),
        eligible_ledger_rows=3,
        eligible_digest=_DIGEST,
        not_eligible={"legal_hold": 1},
        run_id=uuid.UUID(int=7) if applied else None,
    )


@pytest.fixture
def seen(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    recorded: list[dict[str, Any]] = []

    def fake(**kwargs: Any) -> LedgerExpiryResult:
        recorded.append(kwargs)
        return _result(bool(kwargs["apply"]))

    monkeypatch.setattr(cli, "expire_permission_grant_ledger_rows", fake)
    monkeypatch.setenv("ENVIRONMENT", "test")
    return recorded


def test_a_dry_run_names_the_operator_and_the_tenants_and_prints_count_and_digest(
    seen: list[dict[str, Any]], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main([*_BASE, "--tenant", str(_T), "--tenant", str(_T2)]) == 0
    (kwargs,) = seen
    assert kwargs == {
        "caller": UserCaller(_OP),
        "reason": "TICKET-9: expiry",
        "tenant_ids": [_T, _T2],
        "all_purged": False,
        "after": None,
        "apply": False,
        "confirm_rows": None,
        "confirm_digest": None,
    }
    out = json.loads(capsys.readouterr().out)["result"]
    assert out["applied"] is False and out["run_id"] is None
    assert (out["eligible_ledger_rows"], out["eligible_digest"]) == (3, _DIGEST)
    assert out["not_eligible"] == {"legal_hold": 1}
    assert out["eligible"][0]["tenant_id"] == str(_T)


def test_apply_passes_the_confirmation_through_unchanged(
    seen: list[dict[str, Any]], capsys: pytest.CaptureFixture[str]
) -> None:
    argv = [*_BASE, "--all-purged", "--after", str(_T), "--apply"]
    assert cli.main([*argv, "--confirm-rows", "3", "--confirm-digest", _DIGEST]) == 0
    (kwargs,) = seen
    assert kwargs["apply"] is True and kwargs["all_purged"] is True
    assert (kwargs["after"], kwargs["tenant_ids"]) == (_T, [])
    assert (kwargs["confirm_rows"], kwargs["confirm_digest"]) == (3, _DIGEST)
    assert json.loads(capsys.readouterr().out)["result"]["run_id"] == str(uuid.UUID(int=7))


@pytest.mark.parametrize(
    "bad",
    [
        [],
        ["--tenant", str(_T), "--all-purged"],
        ["--tenant", "not-a-uuid"],
        ["--tenant", str(_T), "--after", str(_T2)],
        ["--tenant", str(_T), "--apply"],
        ["--tenant", str(_T), "--apply", "--confirm-rows", "3"],
        ["--tenant", str(_T), "--apply", "--confirm-digest", _DIGEST],
        ["--tenant", str(_T), "--confirm-rows", "3", "--confirm-digest", _DIGEST],
        ["--tenant", str(_T), "--apply", "--confirm-rows", "x", "--confirm-digest", _DIGEST],
    ],
)
def test_an_unclear_request_is_refused_before_core(
    seen: list[dict[str, Any]], bad: list[str]
) -> None:
    assert cli.main([*_BASE, *bad]) == 2
    assert seen == []


def test_production_needs_its_confirmation(
    seen: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from saas_os.core.config import get_settings

    monkeypatch.setenv("ENVIRONMENT", "production")
    get_settings.cache_clear()
    try:
        assert cli.main([*_BASE, "--tenant", str(_T)]) == 2
        assert seen == []
    finally:
        get_settings.cache_clear()


def test_a_refusal_is_exit_one_and_prints_only_the_type(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from saas_os.core.permission_grants import LedgerExpiryConfirmationMismatchError

    def refuse(**kwargs: Any) -> LedgerExpiryResult:
        raise LedgerExpiryConfirmationMismatchError()

    monkeypatch.setattr(cli, "expire_permission_grant_ledger_rows", refuse)
    monkeypatch.setenv("ENVIRONMENT", "test")
    argv = [*_BASE, "--tenant", str(_T), "--apply"]
    assert cli.main([*argv, "--confirm-rows", "3", "--confirm-digest", _DIGEST]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "failed: LedgerExpiryConfirmationMismatchError"


def test_the_command_never_opens_the_application_connection() -> None:
    """It imports neither the application engine nor the application-role
    guard: its only connection is the migrations role's, opened by Core."""
    source = cli.__file__
    with open(source, encoding="utf-8") as handle:
        text = handle.read()
    for name in ("get_engine", "validate_application_role", "session_scope", "DATABASE_URL ="):
        assert name not in text, name


# --- the authorised form (owner decisions of 2026-11-03) ----------------------------------

_AUTH = uuid.uuid4()


@pytest.fixture
def authorised(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, dict[str, Any]]]:
    from saas_os.core.permission_grants.expiry import AuthorizedLedgerDeletionResult

    recorded: list[tuple[Any, dict[str, Any]]] = []

    def fake(authorization_id: Any, **kwargs: Any) -> AuthorizedLedgerDeletionResult:
        recorded.append((authorization_id, kwargs))
        return AuthorizedLedgerDeletionResult(
            as_of=datetime(2026, 11, 3, tzinfo=UTC),
            applied=False,
            execution_authorization_id=authorization_id,
            approval_id=uuid.UUID(int=1),
            request_id=uuid.UUID(int=2),
            authorized_by_user_id=uuid.UUID(int=3),
            tenants=(),
            eligible_ledger_rows=3,
            eligible_digest=_DIGEST,
            scope_digest=_DIGEST,
            audit_id=uuid.UUID(int=4),
        )

    monkeypatch.setattr(cli, "execute_authorized_permission_grant_ledger_deletion", fake)
    monkeypatch.setattr(cli, "expire_permission_grant_ledger_rows", lambda **k: pytest.fail())
    monkeypatch.setenv("ENVIRONMENT", "test")
    return recorded


@pytest.mark.parametrize("apply", [False, True])
def test_the_authorised_form_passes_only_the_authorisation_and_apply(
    authorised: list[tuple[Any, dict[str, Any]]],
    capsys: pytest.CaptureFixture[str],
    apply: bool,
) -> None:
    argv = ["--execution-authorization", str(_AUTH), "--reason", "TICKET-9"]
    assert cli.main([*argv, *(["--apply"] if apply else [])]) == 0
    assert authorised == [(_AUTH, {"reason": "TICKET-9", "apply": apply})]
    out = json.loads(capsys.readouterr().out)["result"]
    assert out["execution_authorization_id"] == str(_AUTH) and out["audit_id"]


@pytest.mark.parametrize(
    "extra",
    [
        ["--operator", str(_OP)],
        ["--tenant", str(_T)],
        ["--all-purged"],
        ["--after", str(_T)],
        ["--confirm-rows", "3"],
        ["--confirm-digest", _DIGEST],
    ],
)
def test_the_authorised_form_refuses_anything_that_names_a_person_or_a_scope(
    authorised: list[tuple[Any, dict[str, Any]]], extra: list[str]
) -> None:
    argv = ["--execution-authorization", str(_AUTH), "--reason", "TICKET-9", *extra]
    assert cli.main(argv) == 2
    assert authorised == []


def test_without_an_authorisation_an_operator_is_required(
    authorised: list[tuple[Any, dict[str, Any]]],
) -> None:
    assert cli.main(["--tenant", str(_T), "--reason", "TICKET-9"]) == 2
    assert cli.main(["--execution-authorization", "nope", "--reason", "TICKET-9"]) == 2
    assert authorised == []


def test_apply_in_the_authorised_form_is_refused_while_deletion_is_disabled(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The real Core function: `deletion_disabled` before any connection."""
    import saas_os.core.permission_grants.expiry as expiry

    attempts: list[Any] = []
    monkeypatch.setattr(expiry, "migrations_role_session_scope", lambda **k: attempts.append(k))
    monkeypatch.setattr(expiry, "_record_denied_for", lambda *a: attempts.append(a))
    monkeypatch.setenv("ENVIRONMENT", "test")
    argv = ["--execution-authorization", str(_AUTH), "--reason", "TICKET-9", "--apply"]
    assert cli.main(argv) == 1
    assert capsys.readouterr().err.strip() == "failed: LedgerDeletionDisabledError"
    assert attempts == [(_AUTH, "deletion_disabled")]  # only the attributed denied row
