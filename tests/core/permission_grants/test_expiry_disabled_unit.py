"""Deleting expired permission grant ledger rows is disabled (owner
decision of 2026-11-02, separation of duties). No database: the run's
connection is replaced by a recorder, so these tests show that `apply` is
refused before the run connects, whoever is named, and that only the
best-effort `denied` audit write is attempted."""

from __future__ import annotations

import ast
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from saas_os.core.authority import UserCaller
from saas_os.core.permission_grants import (
    InvalidLedgerRetentionRequestError,
    LedgerDeletionDisabledError,
    PermissionGrantLedgerRetentionError,
    expiry,
)

_REPO = Path(__file__).resolve().parents[3]
_DIGEST = "a" * 64  # pragma: allowlist secret -- a placeholder digest


class _Recorder:
    def __init__(self) -> None:
        self.opened = 0
        self.denied: list[str] = []

    @contextmanager
    def scope(self, **_: Any):  # type: ignore[no-untyped-def]
        self.opened += 1
        yield object()


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    rec = _Recorder()
    monkeypatch.setattr(expiry, "migrations_role_session_scope", rec.scope)
    monkeypatch.setattr(expiry, "_record_denied", lambda caller, code: rec.denied.append(code))
    return rec


def test_the_shipped_gate_is_off_and_is_a_literal() -> None:
    assert expiry._DELETION_ENABLED is False  # pyright: ignore[reportPrivateUsage]
    tree = ast.parse(
        (_REPO / "saas_os/core/permission_grants/expiry.py").read_text(encoding="utf-8")
    )
    assignments = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(getattr(t, "id", None) == "_DELETION_ENABLED" for t in node.targets)
    ]
    assert len(assignments) == 1
    value = assignments[0].value
    assert isinstance(value, ast.Constant) and value.value is False


def test_apply_with_a_well_formed_confirmation_is_refused_before_the_run_connects(
    recorder: _Recorder,
) -> None:
    with pytest.raises(LedgerDeletionDisabledError) as refused:
        expiry.expire_permission_grant_ledger_rows(
            caller=UserCaller(uuid.uuid4()),
            reason="TICKET-9: retention expiry",
            tenant_ids=[uuid.uuid4()],
            apply=True,
            confirm_rows=3,
            confirm_digest=_DIGEST,
        )
    assert isinstance(refused.value, PermissionGrantLedgerRetentionError)
    assert refused.value.code == "deletion_disabled"
    assert recorder.opened == 0
    assert recorder.denied == ["deletion_disabled"]


def test_a_malformed_apply_is_still_an_invalid_request_first(recorder: _Recorder) -> None:
    with pytest.raises(InvalidLedgerRetentionRequestError):
        expiry.expire_permission_grant_ledger_rows(
            caller=UserCaller(uuid.uuid4()),
            reason="TICKET-9",
            tenant_ids=[uuid.uuid4()],
            apply=True,
        )
    assert recorder.opened == 0
    assert recorder.denied == ["invalid_request"]


def test_the_dry_run_is_not_affected_by_the_gate(
    recorder: _Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The report path opens its connection as before (and here stops at
    the authorization step, which the recorder's dummy session cannot
    satisfy): the gate concerns `apply` only."""
    sentinel = RuntimeError("authorize reached")

    def _authorize(*_: Any, **__: Any) -> None:
        raise sentinel

    monkeypatch.setattr(expiry, "authorize_platform_caller", _authorize)
    with pytest.raises(RuntimeError) as reached:
        expiry.expire_permission_grant_ledger_rows(
            caller=UserCaller(uuid.uuid4()), reason="TICKET-9", tenant_ids=[uuid.uuid4()]
        )
    assert reached.value is sentinel
    assert recorder.opened == 1
