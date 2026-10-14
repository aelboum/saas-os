"""Every platform operator is someone who can log in, against a real
PostgreSQL (ADR-0045 section 6, as amended 2026-10-14).

Enrollment -- through the operation, the bootstrap and the recovery, which
share it -- refuses a user linked to no external identity, with one
`denied` row. Identity erasure removes the links in the same transaction,
under the same platform-owners lock, as its operator check, so the two
serialize: whichever commits first, no operator is left that nobody can log
in as.

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from platform_helpers import (
    ALL_PERMISSIONS,
    BOOTSTRAP,
    REASON,
    Gate,
    PlatformWorld,
    run_first_then_second,
)
from sqlalchemy import Engine

import saas_os.core.platform_authority.owners as platform_owners
import saas_os.core.platform_authority.service as service_module
from saas_os.api.platform_admin.router import _translated
from saas_os.core.identity.erasure import erase_user_identity
from saas_os.core.platform_authority import (
    EnrolledOperatorErasureError,
    PlatformSubjectNotLinkedError,
    bootstrap_platform_owner,
    enroll_operator,
    recover_platform_authority,
)

pytestmark = pytest.mark.integration

_ENROLL = "platform.operator.enroll"


def _links(platform: PlatformWorld, user_id: uuid.UUID) -> int:
    return platform.scalar(
        "SELECT count(*) FROM core.external_identities WHERE user_id = :u", {"u": user_id}
    )


def _operators(platform: PlatformWorld, user_id: uuid.UUID) -> int:
    return platform.scalar(
        "SELECT count(*) FROM core.platform_operators WHERE user_id = :u", {"u": user_id}
    )


def test_a_user_nobody_can_log_in_as_is_not_enrolled(platform: PlatformWorld) -> None:
    owner, _ = platform.owner()
    unlinked = platform.unlinked_user()
    platform.clear_audit()

    with pytest.raises(PlatformSubjectNotLinkedError) as raised:
        enroll_operator(unlinked, caller=owner, reason=REASON)

    assert raised.value.code == "subject_not_linked" and raised.value.user_id == unlinked
    assert _operators(platform, unlinked) == 0
    (denied,) = platform.audit()
    assert (denied["action"], denied["outcome"], denied["reason"]) == (
        _ENROLL,
        "denied",
        "subject_not_linked",
    )
    assert denied["actor_user_id"] == owner.user_id
    # Over HTTP: a conflict with the fixed code, like every refusal.
    response = _translated(raised.value)
    assert response is not None
    assert (response.status_code, response.detail) == (409, "subject_not_linked")


def test_a_linked_user_is_enrolled(platform: PlatformWorld) -> None:
    owner, _ = platform.owner()
    linked = platform.user()
    operator = enroll_operator(linked, caller=owner, reason=REASON)
    assert operator.user_id == linked and operator.status == "active"


def test_an_erased_user_is_not_enrolled(platform: PlatformWorld) -> None:
    owner, _ = platform.owner()
    person = platform.user()
    erase_user_identity(person, [], actor_user_id=owner.user_id)
    assert _links(platform, person) == 0

    with pytest.raises(PlatformSubjectNotLinkedError):
        enroll_operator(person, caller=owner, reason=REASON)
    assert _operators(platform, person) == 0


def test_the_bootstrap_does_not_make_an_owner_nobody_can_log_in_as(
    platform: PlatformWorld,
) -> None:
    """The bootstrap by user id shares the enrollment: the same refusal,
    and no owner exists afterwards."""
    unlinked = platform.unlinked_user()
    with pytest.raises(PlatformSubjectNotLinkedError):
        bootstrap_platform_owner(unlinked, ALL_PERMISSIONS, caller=BOOTSTRAP, reason=REASON)
    assert platform.owner_count() == 0
    assert _operators(platform, unlinked) == 0
    (denied,) = platform.audit(outcome="denied")
    assert (denied["action"], denied["reason"]) == (_ENROLL, "subject_not_linked")
    # Like the recovery's refusals: the composite named, no identity carried.
    assert denied["metadata"] == {"bootstrap": True}
    assert denied["actor_user_id"] is None and denied["target_id"] is None


def test_the_recovery_neither_enrolls_nor_reuses_an_operator_nobody_can_log_in_as(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Recovery enrolling an unlinked user is refused like the operation.
    Reusing an existing active operator that has no link -- one enrolled
    before the amendment, made here with the check switched off -- is
    refused as well, and nothing is granted to it."""
    platform.owner()
    unlinked = platform.unlinked_user()
    platform.clear_audit()
    with pytest.raises(PlatformSubjectNotLinkedError):
        recover_platform_authority(
            caller=BOOTSTRAP,
            reason=REASON,
            enroll_user_id=unlinked,
            grant_permissions=ALL_PERMISSIONS,
        )
    assert _operators(platform, unlinked) == 0
    (denied,) = platform.audit(outcome="denied")
    assert denied["reason"] == "subject_not_linked" and denied["metadata"] == {"recovery": True}

    with monkeypatch.context() as patched:
        patched.setattr(service_module, "lock_external_identity_exists", lambda *a, **k: True)
        legacy = enroll_operator(unlinked, caller=BOOTSTRAP, reason=REASON)
    platform.clear_audit()
    with pytest.raises(PlatformSubjectNotLinkedError):
        recover_platform_authority(
            caller=BOOTSTRAP,
            reason=REASON,
            enroll_user_id=unlinked,
            grant_permissions=ALL_PERMISSIONS,
        )
    assert platform.live_permissions(legacy.id) == set()
    (denied,) = platform.audit(outcome="denied")
    assert denied["reason"] == "subject_not_linked"

    # A linked user is enrolled by the recovery as before.
    linked = platform.user()
    result = recover_platform_authority(
        caller=BOOTSTRAP, reason=REASON, enroll_user_id=linked, grant_permissions=ALL_PERMISSIONS
    )
    assert result.enrolled_operator_id is not None


def test_enrollment_first_then_erasure_refuses_the_erasure_and_keeps_the_login(
    admin: Engine, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The enrollment holds the platform-owners lock, its operator row
    written but not committed, while the erasure starts and waits; the
    erasure then sees the operator and is refused with nothing deleted."""
    owner, _ = platform.owner()
    person = platform.user()
    pause = Gate("first")
    original = service_module.record_platform_event_in_transaction

    def gated(session: Any, **kwargs: Any) -> Any:
        pause.checkpoint(session)
        return original(session, **kwargs)

    monkeypatch.setattr(service_module, "record_platform_event_in_transaction", gated)
    first, second = run_first_then_second(
        admin,
        pause,
        lambda: enroll_operator(person, caller=owner, reason=REASON),
        lambda: erase_user_identity(person, [], actor_user_id=owner.user_id),
    )

    assert "error" not in first, first
    assert isinstance(second.get("error"), EnrolledOperatorErasureError), second
    assert _links(platform, person) == 1  # the operator can still log in
    assert platform.operator_status(first["result"].id) == "active"


def test_erasure_first_then_enrollment_refuses_the_enrollment(
    admin: Engine, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The erasure holds the platform-owners lock, past its operator check,
    while the enrollment starts and waits; the enrollment then finds no
    link and is refused."""
    owner, _ = platform.owner()
    person = platform.user()
    pause = Gate("first")
    original = platform_owners.unrevoked_operator_exists

    def gated(session: Any, user_id: uuid.UUID) -> bool:
        pause.checkpoint(session)
        return original(session, user_id)

    monkeypatch.setattr(platform_owners, "unrevoked_operator_exists", gated)
    first, second = run_first_then_second(
        admin,
        pause,
        lambda: erase_user_identity(person, [], actor_user_id=owner.user_id),
        lambda: enroll_operator(person, caller=owner, reason=REASON),
    )

    assert "error" not in first, first
    assert isinstance(second.get("error"), PlatformSubjectNotLinkedError), second
    assert _links(platform, person) == 0 and _operators(platform, person) == 0


def test_without_the_check_a_user_nobody_can_log_in_as_is_enrolled(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: with the check removed, the refused user of the
    first test becomes an operator nobody can use."""
    owner, _ = platform.owner()
    unlinked = platform.unlinked_user()
    with pytest.raises(PlatformSubjectNotLinkedError):
        enroll_operator(unlinked, caller=owner, reason=REASON)
    monkeypatch.setattr(service_module, "lock_external_identity_exists", lambda *a, **k: True)
    enroll_operator(unlinked, caller=owner, reason=REASON)
    assert _operators(platform, unlinked) == 1
