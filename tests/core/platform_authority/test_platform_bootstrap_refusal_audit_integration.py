"""A bootstrap or recovery attempted with the wrong system purpose is
refused **and recorded**, against a real PostgreSQL (ADR-0045 sections 5a,
5b and 8).

Regression. The two composites used to pass their own names
(`platform.bootstrap`, `platform.recover`) to the refusal writer as the
audit action. Neither is an action of the declared operation table, the
writer rejected them, and -- the refusal row being best effort -- that
failure was swallowed: the refusal was raised, nothing changed, and no
evidence of the attempt was written. A refusal row now reuses the action
of the operation that was refused, as ADR-0045 section 5b specifies and as
every other refusal already did.

Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import json
import uuid

import pytest
from platform_helpers import ALL_PERMISSIONS, BOOTSTRAP, REASON, PlatformWorld

from saas_os.core.authority import (
    CallerTypeError,
    ServiceAccountCaller,
    SystemAuthority,
    SystemCaller,
    UserCaller,
)
from saas_os.core.platform_authority import (
    PLATFORM_OPERATIONS,
    OperatorIdentity,
    PlatformNotAuthorizedError,
    PlatformPermission,
    bootstrap_platform_owner,
    recover_platform_authority,
)

pytestmark = pytest.mark.integration

_WRONG_PURPOSES = [
    SystemAuthority.PROVISIONING,
    SystemAuthority.TENANT_PURGE,
    SystemAuthority.BILLING_OPERATIONS,
]
_ISSUER = "https://idp.refusal-audit.test"
_SUBJECT = "subject-that-must-not-be-recorded"
_DECLARED_ACTIONS = {row.audit_action for row in PLATFORM_OPERATIONS.values()}


def _state(platform: PlatformWorld) -> tuple[int, int, int, int]:
    return (
        platform.scalar("SELECT count(*) FROM core.platform_operators"),
        platform.scalar("SELECT count(*) FROM core.platform_grants"),
        platform.scalar("SELECT count(*) FROM core.users"),
        platform.scalar(
            "SELECT count(*) FROM core.external_identities WHERE issuer = :i", {"i": _ISSUER}
        ),
    )


def _assert_one_safe_denied_row(
    platform: PlatformWorld, *, action: str, purpose: SystemAuthority, marker: str
) -> None:
    rows = platform.audit()
    assert len(rows) == 1, rows
    (row,) = rows
    assert row["outcome"] == "denied" and row["reason"] == "not_authorized"
    assert row["action"] == action and action in _DECLARED_ACTIONS
    # The actor is the purpose that was presented -- never a person.
    assert row["actor_type"] == "system" and row["actor_user_id"] is None
    assert row["system_authority"] == purpose.value
    assert row["target_type"] == "platform_operator"
    assert row["target_id"] is None and row["target_tenant_id"] is None
    assert row["metadata"] == {marker: True}
    # Nothing sensitive: no issuer, no subject, no user id, no credential.
    serialized = json.dumps(row, default=str)
    for forbidden in (_ISSUER, _SUBJECT, "token", "secret", "password", "key"):
        assert forbidden not in serialized, forbidden


@pytest.mark.parametrize("purpose", _WRONG_PURPOSES)
def test_bootstrap_with_the_wrong_system_purpose_is_refused_and_audited(
    platform: PlatformWorld, purpose: SystemAuthority
) -> None:
    before = _state(platform)
    with pytest.raises(PlatformNotAuthorizedError):
        bootstrap_platform_owner(
            OperatorIdentity(_ISSUER, _SUBJECT),
            ALL_PERMISSIONS,
            caller=SystemCaller(purpose),
            reason=REASON,
        )
    assert _state(platform) == before == (0, 0, before[2], 0)  # nothing was created
    assert platform.owner_count() == 0
    _assert_one_safe_denied_row(
        platform, action="platform.operator.enroll", purpose=purpose, marker="bootstrap"
    )


@pytest.mark.parametrize("purpose", _WRONG_PURPOSES)
def test_recovery_with_the_wrong_system_purpose_is_refused_and_audited(
    platform: PlatformWorld, purpose: SystemAuthority
) -> None:
    _, sole_owner = platform.owner()
    platform.clear_audit()
    before = _state(platform)
    with pytest.raises(PlatformNotAuthorizedError):
        recover_platform_authority(
            caller=SystemCaller(purpose),
            reason=REASON,
            enroll_identity=OperatorIdentity(_ISSUER, _SUBJECT),
            grant_permissions=[PlatformPermission.AUTHORITY_MANAGE],
            suspend_operator_id=sole_owner,
        )
    assert _state(platform) == before  # no operator, grant, user or identity link
    assert platform.operator_status(sole_owner) == "active"
    assert platform.owner_count() == 1
    _assert_one_safe_denied_row(
        platform, action="platform.operator.enroll", purpose=purpose, marker="recovery"
    )


def test_a_refused_recovery_that_only_suspends_is_recorded_as_a_suspension_attempt(
    platform: PlatformWorld,
) -> None:
    """The action is that of the first operation the call asked for."""
    _, operator_id = platform.owner()
    platform.owner()
    platform.clear_audit()
    purpose = SystemAuthority.PROVISIONING
    with pytest.raises(PlatformNotAuthorizedError):
        recover_platform_authority(
            caller=SystemCaller(purpose), reason=REASON, suspend_operator_id=operator_id
        )
    assert platform.operator_status(operator_id) == "active"
    _assert_one_safe_denied_row(
        platform, action="platform.operator.suspend", purpose=purpose, marker="recovery"
    )


def test_the_right_purpose_still_works_and_writes_no_denied_row(platform: PlatformWorld) -> None:
    result = bootstrap_platform_owner(
        platform.user(), ALL_PERMISSIONS, caller=BOOTSTRAP, reason=REASON
    )
    assert result.created and platform.owner_count() == 1
    assert platform.audit(outcome="denied") == []


@pytest.mark.parametrize(
    "caller",
    [None, UserCaller(uuid.uuid4()), ServiceAccountCaller(uuid.uuid4(), uuid.uuid4()), "system"],
)
def test_a_caller_that_is_not_a_system_purpose_is_rejected_before_any_read_or_write(
    platform: PlatformWorld, caller: object
) -> None:
    """Unchanged behaviour: these are type errors, raised before anything
    is read, and nothing can be attributed to them."""
    with pytest.raises(CallerTypeError):
        bootstrap_platform_owner(uuid.uuid4(), ALL_PERMISSIONS, caller=caller, reason=REASON)
    with pytest.raises(CallerTypeError):
        recover_platform_authority(caller=caller, reason=REASON, enroll_user_id=uuid.uuid4())
    assert platform.audit_count() == 0
    assert platform.scalar("SELECT count(*) FROM core.platform_operators") == 0
