"""Each permission-grant operation that needs a person accepts only a
`UserCaller` once authorization has passed, and says so with an explicit
`CallerTypeError`, not an `assert` (which `python -O` strips). Authorization
is replaced by a pass-through here, so the type check itself is what is under
test; no database is used. `revoke_register_entry` has its own file."""

from __future__ import annotations

import contextlib
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock

import pytest

import saas_os.core.permission_grants.apply as apply_module
import saas_os.core.permission_grants.approvals as approvals
import saas_os.core.permission_grants.register as register
from saas_os.core.authority import (
    CallerTypeError,
    ServiceAccountCaller,
    SystemAuthority,
    SystemCaller,
    UserCaller,
)
from saas_os.core.platform_authority.operations import (
    PERMISSION_GRANT_APPLY,
    PERMISSION_GRANT_LEDGER_APPROVER_ENROL,
    PERMISSION_GRANT_LEDGER_DELETION_APPROVE,
    PERMISSION_GRANT_LEDGER_DELETION_EXECUTION_AUTHORIZE,
    PERMISSION_GRANT_LEDGER_DELETION_REQUEST,
    PERMISSION_GRANT_LEDGER_REPRESENTATIVE_CONFIRM,
    PERMISSION_GRANT_LEDGER_REPRESENTATIVE_PROPOSE,
)

_DIGEST = "a" * 64
_REASON = "a sufficiently long reason for the operation"
_FAR = datetime.now(UTC) + timedelta(days=30)


def _call_propose(caller: object) -> object:
    return register.propose_representative_designation(
        uuid.uuid4(),
        caller=caller,
        session_evidence=object(),
        designation_ref="DESIGNATION-1",
        ticket_ref="TICKET-1",
        valid_until=_FAR,
        reason=_REASON,
    )


def _call_confirm(caller: object) -> object:
    return register.confirm_representative_designation(
        uuid.uuid4(),
        uuid.uuid4(),
        caller=caller,
        session_evidence=object(),
        ticket_ref="TICKET-1",
        reason=_REASON,
    )


def _call_enrol(caller: object) -> object:
    return register.enrol_approver(
        uuid.uuid4(),
        caller=caller,
        session_evidence=object(),
        natural_person_ref="PERSON-1",
        verification_ref="VERIFICATION-1",
        authorisation_ref="AUTHORISATION-1",
        ticket_ref="TICKET-1",
        valid_until=_FAR,
        reason=_REASON,
    )


def _call_request(caller: object) -> object:
    return approvals.request_permission_grant_ledger_deletion(
        caller=caller,
        session_evidence=object(),
        tenant_ids=[uuid.uuid4()],
        eligible_ledger_rows=3,
        eligible_digest=_DIGEST,
        reason=_REASON,
    )


def _call_approve(caller: object) -> object:
    return approvals.approve_permission_grant_ledger_deletion(
        uuid.uuid4(),
        caller=caller,
        session_evidence=object(),
        eligible_ledger_rows=3,
        eligible_digest=_DIGEST,
        reason=_REASON,
    )


def _call_authorize_execution(caller: object) -> object:
    return approvals.authorize_permission_grant_ledger_deletion_execution(
        uuid.uuid4(), caller=caller, session_evidence=object(), reason=_REASON
    )


def _call_apply(caller: object) -> object:
    return apply_module.apply_permission_grant_migrations(
        [],
        namespace="reference",
        caller=caller,
        reason=_REASON,
        tenant_ids=[uuid.uuid4()],
    )


# case id -> (module holding the session helpers, operation, caller of the operation)
_SESSION_OPERATIONS: dict[str, tuple[ModuleType, str, Callable[[object], object]]] = {
    "propose": (register, PERMISSION_GRANT_LEDGER_REPRESENTATIVE_PROPOSE, _call_propose),
    "confirm": (register, PERMISSION_GRANT_LEDGER_REPRESENTATIVE_CONFIRM, _call_confirm),
    "enrol": (register, PERMISSION_GRANT_LEDGER_APPROVER_ENROL, _call_enrol),
    "request": (approvals, PERMISSION_GRANT_LEDGER_DELETION_REQUEST, _call_request),
    "approve": (approvals, PERMISSION_GRANT_LEDGER_DELETION_APPROVE, _call_approve),
    "authorize-execution": (
        approvals,
        PERMISSION_GRANT_LEDGER_DELETION_EXECUTION_AUTHORIZE,
        _call_authorize_execution,
    ),
}

_NOT_USERS = pytest.mark.parametrize(
    "caller",
    [
        SystemCaller(SystemAuthority.PROVISIONING),
        ServiceAccountCaller(tenant_id=uuid.uuid4(), service_account_id=uuid.uuid4()),
        None,
        "not-a-caller",
    ],
    ids=["system", "service-account", "none", "string"],
)


@contextlib.contextmanager
def _pass_through(*_args: Any, **_kwargs: Any) -> Iterator[MagicMock]:
    yield MagicMock()


@pytest.mark.parametrize("case", list(_SESSION_OPERATIONS))
@_NOT_USERS
def test_a_caller_that_is_not_a_user_caller_is_refused_with_an_explicit_error(
    case: str, caller: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, operation, call = _SESSION_OPERATIONS[case]
    reached: list[str] = []

    def _verify(*_args: Any, **_kwargs: Any) -> None:
        reached.append("verify_session")
        raise AssertionError("verify_session must not be reached for a non-user caller")

    monkeypatch.setattr(module, "refusals_recorded", _pass_through)
    monkeypatch.setattr(module, "platform_change_session", _pass_through)
    monkeypatch.setattr(module, "authorize_platform_caller", lambda *a, **k: None)
    monkeypatch.setattr(module, "verify_session", _verify)

    with pytest.raises(CallerTypeError) as raised:
        call(caller)

    assert raised.value.operation == operation
    assert raised.value.allowed == (UserCaller,)
    assert reached == []


@_NOT_USERS
def test_apply_refuses_a_caller_that_is_not_a_user_caller_before_any_tenant_is_touched(
    caller: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    reached: list[str] = []

    def _tenant(*_args: Any, **_kwargs: Any) -> None:
        reached.append("_run_tenant")
        raise AssertionError("no tenant may be touched for a non-user caller")

    monkeypatch.setattr(apply_module, "validate_permission_grant_migrations", lambda *a, **k: ())
    monkeypatch.setattr(apply_module, "recording_platform_refusal", _pass_through)
    monkeypatch.setattr(apply_module, "platform_change_session", _pass_through)
    monkeypatch.setattr(apply_module, "authorize_platform_caller", lambda *a, **k: None)
    monkeypatch.setattr(apply_module, "_resolve_permissions", lambda *a, **k: {})
    monkeypatch.setattr(apply_module, "_check_ledgers", lambda *a, **k: None)
    monkeypatch.setattr(apply_module, "_run_tenant", _tenant)

    with pytest.raises(CallerTypeError) as raised:
        _call_apply(caller)

    assert raised.value.operation == PERMISSION_GRANT_APPLY
    assert raised.value.allowed == (UserCaller,)
    assert reached == []
