"""A caller-type requirement is stated with an explicit `CallerTypeError`,
never with an `assert` (which `python -O` strips, leaving the code after
it to run for any caller that got past the earlier checks).

Each operation below has an earlier check that already refuses the other
caller types (`require_caller`, `authorize_platform_caller`, the operation
table). Here that check is replaced by a pass-through, so the type check
that follows it is what is under test, and nothing after it may run. No
database is used. Sessions are mocks; a downstream sentinel fails the test
if the code goes on past the type check."""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Callable, Iterator
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock

import pytest

import saas_os.control_plane.inference.service as inference_service
import saas_os.core.audit_log.service as audit_service
import saas_os.core.billing.authorization as billing_authorization
import saas_os.core.feature_flags.service as flag_service
import saas_os.core.identity.user_authority as user_authority
import saas_os.core.outbox.replay as outbox_replay
import saas_os.core.platform_authority as platform_authority
import saas_os.core.platform_authority.audit as platform_audit
import saas_os.core.platform_authority.authorization as platform_authorization
import saas_os.core.platform_authority.bootstrap as platform_bootstrap
import saas_os.core.tenancy.service as tenancy_service
import saas_os.core.webhooks.reencryption as webhook_reencryption
from saas_os.control_plane.inference.service import OPERATION as INFERENCE_OPERATION
from saas_os.core.authority import (
    CallerTypeError,
    ServiceAccountCaller,
    SystemAuthority,
    SystemCaller,
    UserCaller,
)
from saas_os.core.billing.authorization import AuthorizedBillingCaller
from saas_os.core.platform_authority.errors import PlatformNotAuthorizedError
from saas_os.core.platform_authority.operations import (
    API_KEY_REVOKE,
    FEATURE_FLAG_OVERRIDE,
    OUTBOX_REPLAY,
    TENANT_CREATE_ROOT,
    TENANT_MOVE,
    TENANT_REACTIVATE,
    USER_REACTIVATE,
    WEBHOOK_SECRET_REENCRYPT,
)
from saas_os.core.tenancy import TenantStatus

_REASON = "a sufficiently long reason for the operation"

_SYSTEM = SystemCaller(SystemAuthority.PROVISIONING)
_SERVICE_ACCOUNT = ServiceAccountCaller(tenant_id=uuid.uuid4(), service_account_id=uuid.uuid4())


@contextlib.contextmanager
def _pass_through(*_args: Any, **_kwargs: Any) -> Iterator[MagicMock]:
    yield MagicMock()


def _no_check(*_args: Any, **_kwargs: Any) -> None:
    return None


def _sentinel(name: str, reached: list[str]) -> Callable[..., Any]:
    def _reached(*_args: Any, **_kwargs: Any) -> Any:
        reached.append(name)
        raise AssertionError(f"{name} must not be reached after the caller-type refusal")

    return _reached


def _patch_all(monkeypatch: pytest.MonkeyPatch, module: ModuleType, **replacements: Any) -> None:
    for name, value in replacements.items():
        monkeypatch.setattr(module, name, value)


# ---------------------------------------------------------------- platform operations
# The operations whose table row declares no system purpose: `authorize_platform_caller`
# refuses every SystemCaller for them, so the `UserCaller` check after it is a second
# guard. `authorized` is the pass-through standing in for the first.


def _flag_set(caller: object, monkeypatch: pytest.MonkeyPatch, reached: list[str]) -> None:
    _patch_all(
        monkeypatch,
        flag_service,
        get_flag=lambda key: MagicMock(id=uuid.uuid4()),
        platform_change_session=_pass_through,
        lock_open_tenant=_sentinel("lock_open_tenant", reached),
    )
    flag_service.set_tenant_override(uuid.uuid4(), "flag", True, caller=caller)


def _flag_remove(caller: object, monkeypatch: pytest.MonkeyPatch, reached: list[str]) -> None:
    _patch_all(
        monkeypatch,
        flag_service,
        get_flag=lambda key: MagicMock(id=uuid.uuid4()),
        platform_change_session=_pass_through,
        recording_platform_refusal=_pass_through,
        bind_tenant_scope=_sentinel("bind_tenant_scope", reached),
    )
    flag_service.remove_tenant_override(uuid.uuid4(), "flag", caller=caller)


def _revoke_keys(caller: object, monkeypatch: pytest.MonkeyPatch, reached: list[str]) -> None:
    _patch_all(
        monkeypatch,
        platform_authority,
        platform_change_session=_pass_through,
        authorize_platform_caller=_no_check,
    )
    monkeypatch.setattr(user_authority, "lock_user_is_active", _sentinel("lock_user", reached))
    user_authority.revoke_user_api_keys(uuid.uuid4(), caller=caller, reason=_REASON)


def _reactivate(caller: object, monkeypatch: pytest.MonkeyPatch, reached: list[str]) -> None:
    _patch_all(
        monkeypatch,
        platform_authority,
        platform_change_session=_pass_through,
        authorize_platform_caller=_no_check,
        lock_platform_owners=_no_check,
    )
    monkeypatch.setattr(user_authority, "lock_user_is_active", _sentinel("lock_user", reached))
    user_authority.reactivate_user(uuid.uuid4(), caller=caller, reason=_REASON)


def _replay(caller: object, monkeypatch: pytest.MonkeyPatch, reached: list[str]) -> None:
    _patch_all(
        monkeypatch,
        platform_authority,
        platform_change_session=_pass_through,
        recording_platform_refusal=_pass_through,
        authorize_platform_caller=_no_check,
    )
    _patch_all(
        monkeypatch,
        outbox_replay,
        bind_tenant_scope=_sentinel("bind_tenant_scope", reached),
        database_now=lambda: None,
    )
    outbox_replay.replay_dead_lettered_events(
        uuid.uuid4(), caller=caller, reason=_REASON, event_ids=[uuid.uuid4()], apply=True
    )


def _reencrypt(caller: object, monkeypatch: pytest.MonkeyPatch, reached: list[str]) -> None:
    _patch_all(
        monkeypatch,
        platform_authority,
        platform_change_session=_pass_through,
        recording_platform_refusal=_pass_through,
        authorize_platform_caller=_no_check,
    )
    _patch_all(
        monkeypatch,
        webhook_reencryption,
        _require_usable_key=_sentinel("_require_usable_key", reached),
        bind_tenant_scope=_sentinel("bind_tenant_scope", reached),
    )
    webhook_reencryption.reencrypt_legacy_signing_secrets(
        uuid.uuid4(), caller=caller, reason=_REASON, apply=True
    )


def _move(caller: object, monkeypatch: pytest.MonkeyPatch, reached: list[str]) -> None:
    authority = tenancy_service.lifecycle_authority
    _patch_all(
        monkeypatch,
        authority,
        require_lifecycle_caller=_no_check,
        refusal_recorded=_pass_through,
        change_session=_pass_through,
        authorize=_no_check,
    )
    _patch_all(
        monkeypatch,
        tenancy_service,
        _lock_hierarchy_globally=_no_check,
        _lock_hierarchy_nodes=_no_check,
        lock_open_tenant=_sentinel("lock_open_tenant", reached),
    )
    tenancy_service.move_tenant(uuid.uuid4(), None, caller=caller)


_NO_SYSTEM_PURPOSE: dict[str, tuple[str, Callable[..., None]]] = {
    "flag-set-override": (FEATURE_FLAG_OVERRIDE, _flag_set),
    "flag-remove-override": (FEATURE_FLAG_OVERRIDE, _flag_remove),
    "revoke-user-api-keys": (API_KEY_REVOKE, _revoke_keys),
    "reactivate-user": (USER_REACTIVATE, _reactivate),
    "outbox-replay": (OUTBOX_REPLAY, _replay),
    "webhook-secret-reencrypt": (WEBHOOK_SECRET_REENCRYPT, _reencrypt),
    "tenant-move": (TENANT_MOVE, _move),
}


@pytest.mark.parametrize("case", list(_NO_SYSTEM_PURPOSE))
@pytest.mark.parametrize(
    "caller",
    [
        _SYSTEM,
        SystemCaller(SystemAuthority.TENANT_PURGE),
        _SERVICE_ACCOUNT,
        None,
        "not-a-caller",
    ],
    ids=["system-provisioning", "system-purge", "service-account", "none", "string"],
)
def test_an_operation_that_accepts_only_a_user_refuses_any_other_caller_with_an_explicit_error(
    case: str, caller: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation, call = _NO_SYSTEM_PURPOSE[case]
    reached: list[str] = []
    # The earlier `require_caller` / `_require_person_or_refuse` is not what is tested here.
    for module in (flag_service, user_authority, platform_authorization):
        monkeypatch.setattr(module, "require_caller", _no_check)
    if case.startswith("flag"):
        monkeypatch.setattr(flag_service, "_require_platform_caller", _no_check)
        monkeypatch.setattr(flag_service, "authorize_platform_caller", _no_check)
    if case.startswith("revoke") or case.startswith("reactivate"):
        monkeypatch.setattr(user_authority, "_require_person_or_refuse", _no_check)

    with pytest.raises(CallerTypeError) as raised:
        call(caller, monkeypatch, reached)

    assert raised.value.operation == operation
    assert raised.value.allowed == (UserCaller,)
    assert reached == []


@pytest.mark.parametrize("case", list(_NO_SYSTEM_PURPOSE))
def test_authorization_refuses_a_system_caller_for_these_operations_before_the_type_check(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The earlier check, real: the operation table declares no system purpose for any
    of them, so `authorize_platform_caller` refuses a `SystemCaller` itself."""
    operation, _call = _NO_SYSTEM_PURPOSE[case]
    spec = platform_authority.platform_operation(operation)
    assert spec.system_authorities == frozenset()
    for authority in SystemAuthority:
        with pytest.raises(PlatformNotAuthorizedError):
            platform_authority.authorize_platform_caller(
                SystemCaller(authority), session=MagicMock(), operation=operation
            )


# ---------------------------------------------------------------- tenancy


def _tenancy_double(monkeypatch: pytest.MonkeyPatch, session: MagicMock, **extra: Any) -> None:
    @contextlib.contextmanager
    def _session(*_args: Any, **_kwargs: Any) -> Iterator[MagicMock]:
        yield session

    _patch_all(
        monkeypatch,
        tenancy_service.lifecycle_authority,
        require_lifecycle_caller=_no_check,
        refusal_recorded=_pass_through,
        change_session=_session,
        authorize=_no_check,
        **extra,
    )


def test_create_tenant_refuses_a_caller_that_is_neither_a_user_nor_a_system_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = MagicMock()
    _tenancy_double(monkeypatch, session)

    with pytest.raises(CallerTypeError) as raised:
        tenancy_service.create_tenant("acme", caller=_SERVICE_ACCOUNT)

    assert raised.value.allowed == (UserCaller, SystemCaller)
    assert raised.value.operation == TENANT_CREATE_ROOT
    session.add.assert_not_called()


def test_transition_tenant_status_refuses_a_caller_that_is_neither_a_user_nor_a_system_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = MagicMock(status=TenantStatus.SUSPENDED.value)
    session = MagicMock()
    session.get.return_value = tenant
    _tenancy_double(monkeypatch, session, passes_transition_gate=lambda *a, **k: True)
    monkeypatch.setattr(tenancy_service, "_authorize_transition", lambda *a, **k: False)

    with pytest.raises(CallerTypeError) as raised:
        tenancy_service.transition_tenant_status(
            uuid.uuid4(), TenantStatus.ACTIVE, caller=_SERVICE_ACCOUNT
        )

    assert raised.value.allowed == (UserCaller, SystemCaller)
    assert raised.value.operation == TENANT_REACTIVATE
    assert tenant.status == TenantStatus.SUSPENDED.value
    session.flush.assert_not_called()


# ---------------------------------------------------------------- platform authority


def test_authorize_platform_caller_refuses_an_unknown_caller_type_before_any_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reached: list[str] = []
    monkeypatch.setattr(platform_authorization, "require_caller", _no_check)
    monkeypatch.setattr(platform_authorization, "platform_can", _sentinel("platform_can", reached))

    with pytest.raises(CallerTypeError) as raised:
        platform_authorization.authorize_platform_caller(
            None, session=MagicMock(), operation=OUTBOX_REPLAY
        )

    assert raised.value.operation == OUTBOX_REPLAY
    assert raised.value.allowed == (UserCaller,)
    assert reached == []


@pytest.mark.parametrize(
    "caller", [None, "not-a-caller", _SERVICE_ACCOUNT], ids=["none", "str", "sa"]
)
def test_record_platform_event_refuses_a_caller_that_is_not_a_person_or_a_system_purpose(
    caller: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    reached: list[str] = []
    session = MagicMock()
    monkeypatch.setattr(platform_audit, "require_caller", _no_check)
    monkeypatch.setattr(platform_audit, "_entry", _sentinel("_entry", reached))

    with pytest.raises(CallerTypeError) as raised:
        platform_audit.record_platform_event_in_transaction(
            session, caller=caller, action="platform.test", target_type="test"
        )

    assert raised.value.operation == "record_platform_event_in_transaction"
    assert raised.value.allowed == (UserCaller, SystemCaller)
    assert reached == []
    session.add.assert_not_called()


@pytest.mark.parametrize(
    "caller", [None, "not-a-caller", _SERVICE_ACCOUNT], ids=["none", "str", "sa"]
)
def test_record_platform_refusal_refuses_a_caller_that_is_not_a_person_or_a_system_purpose(
    caller: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    reached: list[str] = []
    monkeypatch.setattr(platform_audit, "require_caller", _no_check)
    monkeypatch.setattr(platform_audit, "_entry", _sentinel("_entry", reached))

    with pytest.raises(CallerTypeError) as raised:
        platform_audit.record_platform_refusal(
            caller=caller, action="platform.test", target_type="test", code="not_authorized"
        )

    assert raised.value.operation == "record_platform_refusal"
    assert raised.value.allowed == (UserCaller, SystemCaller)
    assert reached == []


def test_record_platform_refusal_still_declines_quietly_for_a_service_account() -> None:
    """The documented best-effort behaviour is the earlier check, unchanged."""
    assert (
        platform_audit.record_platform_refusal(
            caller=_SERVICE_ACCOUNT, action="platform.test", target_type="test", code="x"
        )
        is False
    )


@pytest.mark.parametrize(
    "caller", [UserCaller(uuid.uuid4()), None, _SERVICE_ACCOUNT], ids=["user", "none", "sa"]
)
def test_the_bootstrap_caller_check_refuses_anything_but_a_system_caller(
    caller: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    reached: list[str] = []
    monkeypatch.setattr(platform_bootstrap, "require_caller", _no_check)
    monkeypatch.setattr(
        platform_bootstrap, "record_platform_refusal", _sentinel("record_platform_refusal", reached)
    )

    with pytest.raises(CallerTypeError) as raised:
        platform_bootstrap._require_bootstrap_caller(
            "platform.bootstrap", caller, refused_operation=OUTBOX_REPLAY, marker="m"
        )

    assert raised.value.operation == "platform.bootstrap"
    assert raised.value.allowed == (SystemCaller,)
    assert reached == []


# ---------------------------------------------------------------- audit log


@pytest.mark.parametrize("caller", [None, "not-a-caller", object()], ids=["none", "str", "object"])
def test_record_in_transaction_does_not_record_for_a_caller_of_no_known_type(
    caller: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = MagicMock()
    monkeypatch.setattr(audit_service, "require_caller", _no_check)

    with pytest.raises(CallerTypeError) as raised:
        audit_service.record_in_transaction(
            session, caller=caller, tenant_id=uuid.uuid4(), action="a.b", resource_type="t"
        )

    assert raised.value.operation == "record_in_transaction"
    assert raised.value.allowed == (SystemCaller,)
    session.add.assert_not_called()


# ---------------------------------------------------------------- billing


def test_authorize_billing_refuses_a_normalized_caller_of_no_billing_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reached: list[str] = []
    monkeypatch.setattr(
        billing_authorization,
        "require_billing_caller",
        lambda caller: AuthorizedBillingCaller(caller=_SERVICE_ACCOUNT, audit_note={}),
    )
    monkeypatch.setattr(
        billing_authorization, "register_permission", _sentinel("register_permission", reached)
    )

    with pytest.raises(CallerTypeError) as raised:
        billing_authorization.authorize_billing(
            object(),
            [(uuid.uuid4(), "billing", "read")],
            operation="billing.test",
            session=MagicMock(),
        )

    assert raised.value.operation == "billing.test"
    assert raised.value.allowed == (UserCaller,)
    assert reached == []


def test_audit_actor_refuses_an_authorized_caller_that_is_not_a_user_or_a_system_caller() -> None:
    authorized = AuthorizedBillingCaller(caller=_SERVICE_ACCOUNT, audit_note={})

    with pytest.raises(CallerTypeError) as raised:
        billing_authorization.audit_actor(authorized)

    assert raised.value.operation == "audit_actor"
    assert raised.value.allowed == (UserCaller,)


# ---------------------------------------------------------------- inference


@pytest.mark.parametrize("caller", [_SYSTEM, None, "not-a-caller"], ids=["system", "none", "str"])
def test_run_inference_refuses_a_caller_of_the_wrong_type_before_reading_anything(
    caller: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    reached: list[str] = []
    monkeypatch.setattr(inference_service, "require_caller", _no_check)
    monkeypatch.setattr(inference_service, "_total_deadline", _sentinel("_total_deadline", reached))

    with pytest.raises(CallerTypeError) as raised:
        asyncio.run(
            inference_service.run_inference(
                caller,
                tenant_id=uuid.uuid4(),
                request=MagicMock(),
                runtime=MagicMock(),
            )
        )

    assert raised.value.operation == INFERENCE_OPERATION
    assert raised.value.allowed == (UserCaller, ServiceAccountCaller)
    assert reached == []
