"""Identity erasure and platform operators against a real PostgreSQL
(ADR-0045 section 6): `erase_user_identity` refuses a user who has a
platform operator row that is not revoked, before it erases anything.

Erasing an operator's identity would end that person's access without
passing through the last-owner invariant. The refusal sends the caller to
`revoke_operator`, which does pass through it.

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from phase_c_helpers import REASON, P, Scene
from platform_helpers import BOOTSTRAP, PlatformWorld

import saas_os.core.platform_authority.owners as platform_owners
from saas_os.core.identity.erasure import erase_user_identity
from saas_os.core.identity.service import get_or_create_user_for_external_identity
from saas_os.core.platform_authority import (
    EnrolledOperatorErasureError,
    enroll_operator,
    grant_platform_permission,
    revoke_operator,
    suspend_operator,
)

pytestmark = pytest.mark.integration

_ISSUER = "https://issuer.phase-c.test"


class _Subject:
    """A user with everything erasure removes: an external identity, a
    live session, and a membership with an API key in one tenant."""

    def __init__(self, scene: Scene, platform: PlatformWorld) -> None:
        self.scene, self.platform = scene, platform
        self.user_id = get_or_create_user_for_external_identity(
            _ISSUER, f"subject-{uuid.uuid4().hex}"
        ).id
        platform.users.append(self.user_id)
        self.tenant = scene.tenant(active=True)
        scene.admin(self.tenant)  # the tenant keeps an administrator of its own
        scene.join(self.tenant, self.user_id)
        scene.api_key(self.tenant, self.user_id)
        scene.session_for(self.user_id)

    def enroll(self, permissions: tuple[Any, ...] = ()) -> uuid.UUID:
        operator = enroll_operator(self.user_id, caller=BOOTSTRAP, reason=REASON)
        for permission in permissions:
            grant_platform_permission(operator.id, permission, caller=BOOTSTRAP, reason=REASON)
        return operator.id

    def state(self) -> dict[str, int]:
        count = self.platform.scalar
        user = {"u": self.user_id}
        return {
            "external_identities": count(
                "SELECT count(*) FROM core.external_identities WHERE user_id = :u", user
            ),
            "sessions": count("SELECT count(*) FROM core.sessions WHERE user_id = :u", user),
            "memberships": count(
                "SELECT count(*) FROM core.tenant_memberships WHERE user_id = :u", user
            ),
            "api_keys": count("SELECT count(*) FROM core.api_keys WHERE user_id = :u", user),
        }


@pytest.fixture
def subject(scene: Scene, platform: PlatformWorld) -> Iterator[_Subject]:
    made = _Subject(scene, platform)
    yield made
    # A refused erasure leaves these in place; the user row goes with the
    # platform fixture's own teardown.
    platform.execute("DELETE FROM core.external_identities WHERE user_id = :u", {"u": made.user_id})


_FULL = {"external_identities": 1, "sessions": 1, "memberships": 1, "api_keys": 1}
_ERASED = {"external_identities": 0, "sessions": 0, "memberships": 0, "api_keys": 0}


def _erasure_rows(scene: Scene, tenant: uuid.UUID) -> list[dict[str, Any]]:
    return scene.tenant_audit(tenant, "identity.erasure_membership_removed")


@pytest.mark.parametrize("suspended", [False, True])
def test_erasure_of_an_enrolled_operator_is_refused_and_changes_nothing(
    scene: Scene, platform: PlatformWorld, subject: _Subject, suspended: bool
) -> None:
    owner, _ = platform.owner()
    operator_id = subject.enroll((P.TENANT_READ,))
    if suspended:  # a suspended operator is still enrolled
        suspend_operator(operator_id, caller=owner, reason=REASON)
    actor = platform.user()
    platform.clear_audit()

    with pytest.raises(EnrolledOperatorErasureError):
        erase_user_identity(subject.user_id, [subject.tenant], actor_user_id=actor)

    assert subject.state() == _FULL  # identity, session, membership and key untouched
    assert platform.operator_status(operator_id) == ("suspended" if suspended else "active")
    assert _erasure_rows(scene, subject.tenant) == []  # no tenant evidence of an erasure
    # One refusal row, by the existing contract; no success row of any kind.
    rows = platform.audit()
    assert len(rows) == 1
    assert rows[0]["action"] == "platform.user.erase" and rows[0]["outcome"] == "denied"
    assert rows[0]["reason"] == "enrolled_operator"
    assert rows[0]["actor_user_id"] == actor and rows[0]["target_id"] == str(subject.user_id)
    assert rows[0]["target_tenant_id"] is None and rows[0]["metadata"] is None


def test_erasure_of_the_last_owner_is_refused_and_ownership_is_intact(
    scene: Scene, platform: PlatformWorld, subject: _Subject
) -> None:
    subject.enroll(tuple(P))  # the only owner of the installation
    assert platform.owner_count() == 1
    actor = platform.user()

    with pytest.raises(EnrolledOperatorErasureError):
        erase_user_identity(subject.user_id, [subject.tenant], actor_user_id=actor)

    # Still an owner who can log in: the identity link and session remain.
    assert platform.owner_count() == 1 and subject.state() == _FULL
    assert scene.user_is_active(subject.user_id)


def test_once_the_operator_is_revoked_the_identity_can_be_erased(
    scene: Scene, platform: PlatformWorld, subject: _Subject
) -> None:
    owner, _ = platform.owner()
    operator_id = subject.enroll((P.TENANT_READ,))
    actor = platform.user()
    with pytest.raises(EnrolledOperatorErasureError):
        erase_user_identity(subject.user_id, [subject.tenant], actor_user_id=actor)

    revoke_operator(operator_id, caller=owner, reason=REASON)  # the guarded path
    platform.clear_audit()
    result = erase_user_identity(subject.user_id, [subject.tenant], actor_user_id=actor)

    assert result.external_identities_deleted == 1 and result.sessions_deleted == 1
    assert result.tenants_with_membership_removed == (subject.tenant,)
    assert subject.state() == _ERASED
    assert platform.audit(action="platform.user.erase") == []  # nothing was refused
    assert len(_erasure_rows(scene, subject.tenant)) == 1


def test_erasure_of_a_user_who_was_never_an_operator_is_unchanged(
    scene: Scene, platform: PlatformWorld, subject: _Subject
) -> None:
    platform.owner()  # operators exist; the subject is not one of them
    actor = platform.user()
    platform.clear_audit()

    result = erase_user_identity(subject.user_id, [subject.tenant], actor_user_id=actor)

    assert result.external_identities_deleted == 1 and result.sessions_deleted == 1
    assert result.api_keys_deleted == 1
    assert subject.state() == _ERASED
    assert platform.audit_count() == 0  # erasure is not a platform operation: no platform row
    rows = _erasure_rows(scene, subject.tenant)
    assert len(rows) == 1 and rows[0]["actor_user_id"] == actor


def test_without_the_safeguard_an_enrolled_operator_is_erased(
    scene: Scene, platform: PlatformWorld, subject: _Subject, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: with the check removed, the refusal test's
    subject loses its identity while still enrolled."""
    operator_id = subject.enroll((P.TENANT_READ,))
    actor = platform.user()
    # The check alone removed: the links are still deleted in the same step.
    monkeypatch.setattr(platform_owners, "unrevoked_operator_exists", lambda *args, **kwargs: False)

    erase_user_identity(subject.user_id, [subject.tenant], actor_user_id=actor)

    assert subject.state() == _ERASED
    assert platform.operator_status(operator_id) == "active"  # an operator nobody can log in as
