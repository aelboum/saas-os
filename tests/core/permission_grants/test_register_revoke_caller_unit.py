"""`revoke_register_entry()` accepts only a `UserCaller` once authorization
has passed, and says so with an explicit error, not an `assert` (which
`python -O` strips). The authorization step is replaced by a pass-through
here, so the type check itself is what is under test; no database is used."""

from __future__ import annotations

import ast
import contextlib
import inspect
import textwrap
import uuid
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest

import saas_os.core.permission_grants.register as register
from saas_os.core.authority import (
    CallerTypeError,
    ServiceAccountCaller,
    SystemAuthority,
    SystemCaller,
    UserCaller,
)
from saas_os.core.platform_authority.operations import (
    PERMISSION_GRANT_LEDGER_APPROVER_REVOKE_BY_SECURITY,
)

_OPERATION = PERMISSION_GRANT_LEDGER_APPROVER_REVOKE_BY_SECURITY


@pytest.fixture
def later_steps(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replaces authorization by a pass-through; records any later step."""
    reached: list[str] = []

    @contextlib.contextmanager
    def _refusals(*_args: Any) -> Iterator[None]:
        yield

    @contextlib.contextmanager
    def _change_session(*_args: Any) -> Iterator[MagicMock]:
        yield MagicMock()

    def _verify(*_args: Any, **_kwargs: Any) -> None:
        reached.append("verify_session")
        raise AssertionError("verify_session must not be reached for a non-user caller")

    monkeypatch.setattr(register, "refusals_recorded", _refusals)
    monkeypatch.setattr(register, "platform_change_session", _change_session)
    monkeypatch.setattr(register, "authorize_platform_caller", lambda *a, **k: None)
    monkeypatch.setattr(register, "verify_session", _verify)
    return reached


def _revoke(caller: object) -> None:
    register.revoke_register_entry(
        uuid.uuid4(),
        uuid.uuid4(),
        operation=_OPERATION,
        caller=caller,
        session_evidence=object(),
        ticket_ref="TICKET-1",
        reason="a sufficiently long reason for the revocation",
    )


@pytest.mark.parametrize(
    "caller",
    [
        SystemCaller(SystemAuthority.PROVISIONING),
        ServiceAccountCaller(tenant_id=uuid.uuid4(), service_account_id=uuid.uuid4()),
        None,
        "not-a-caller",
    ],
    ids=["system", "service-account", "none", "string"],
)
def test_a_caller_that_is_not_a_user_caller_is_refused_with_an_explicit_error(
    caller: object, later_steps: list[str]
) -> None:
    with pytest.raises(CallerTypeError) as raised:
        _revoke(caller)

    assert raised.value.operation == _OPERATION
    assert raised.value.allowed == (UserCaller,)
    assert later_steps == []


def test_the_type_check_is_not_an_assert_statement() -> None:
    tree = ast.parse(textwrap.dedent(inspect.getsource(register.revoke_register_entry)))
    assert not [node for node in ast.walk(tree) if isinstance(node, ast.Assert)]
