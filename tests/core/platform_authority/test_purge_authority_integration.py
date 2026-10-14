"""`purge_tenant` takes a caller, against a real PostgreSQL
(ADR-0045 section 12; the owner-approved correction of 2026-10-14).

Purge has no platform permission. The operation it performs,
`tenant.purge_transition`, accepts exactly `SystemCaller(TENANT_PURGE)`;
every other caller is refused before the tenant is read, with one `denied`
row. Each of its two transitions is authorized in its own transaction and
leaves a `platform.tenant.purge_transition` row there.

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from phase_c_helpers import BILLING, PROVISIONING, TENANT_PURGE, P, Scene
from platform_helpers import BOOTSTRAP, PlatformWorld

import saas_os.core.tenancy.authority as lifecycle_authority
from saas_os.core.authority import CallerTypeError, ServiceAccountCaller, UserCaller
from saas_os.core.platform_authority import InvalidPlatformRequestError, PlatformNotAuthorizedError
from saas_os.core.tenancy import TenantStatus, purge_tenant
from saas_os.core.tenancy.purge_participants import TenantPurgeParticipantRegistry

pytestmark = pytest.mark.integration

_ACTION = "platform.tenant.purge_transition"


def _deleted_tenant(scene: Scene) -> uuid.UUID:
    tenant = scene.tenant(active=True)
    scene.set_status(tenant, TenantStatus.DELETED)
    return tenant


def _purge(tenant: uuid.UUID, caller: Any, **kwargs: Any) -> Any:
    return purge_tenant(tenant, caller=caller, registry=TenantPurgeParticipantRegistry(), **kwargs)


def test_the_purge_authority_purges_and_both_transitions_leave_a_platform_row(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = _deleted_tenant(scene)
    person = platform.user()
    platform.clear_audit()

    result = _purge(tenant, TENANT_PURGE, actor_user_id=person)

    assert result.already_purged is False and scene.status(tenant) == "purged"
    rows = platform.audit(action=_ACTION)
    assert [(row["outcome"], row["metadata"]["to_status"]) for row in rows] == [
        ("success", "purging"),
        ("success", "purged"),
    ]
    for row in rows:
        assert row["actor_type"] == "system" and row["system_authority"] == "tenant_purge"
        assert row["target_tenant_id"] == tenant and row["target_id"] == str(tenant)
        # Who ran it, for attribution; it authorizes nothing.
        assert row["metadata"]["run_by_user_id"] == str(person)
    assert rows[0]["metadata"]["from_status"] == "deleted"
    assert rows[1]["metadata"]["from_status"] == "purging"
    # The tenant's own trail is unchanged: started and completed.
    actions = [row["action"] for row in scene.tenant_audit(tenant)]
    assert "tenant.purge_started" in actions and "tenant.purge_completed" in actions


def test_an_already_purged_tenant_writes_nothing_and_a_resume_writes_only_the_final_row(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = _deleted_tenant(scene)
    _purge(tenant, TENANT_PURGE)
    platform.clear_audit()
    assert _purge(tenant, TENANT_PURGE).already_purged is True
    assert platform.audit() == []  # nothing happened

    resumed = scene.tenant(active=True)
    scene.set_status(resumed, TenantStatus.PURGING)  # a purge that stopped part-way
    platform.clear_audit()
    _purge(resumed, TENANT_PURGE)
    assert [row["metadata"]["to_status"] for row in platform.audit(action=_ACTION)] == ["purged"]


@pytest.mark.parametrize("status", [None, *TenantStatus])
def test_every_other_caller_is_refused_before_the_tenant_is_read(
    scene: Scene, platform: PlatformWorld, status: TenantStatus | None
) -> None:
    """The same refusal for a missing tenant and for every status, and
    nothing changed: an operator holding every platform permission, an
    ordinary user and every other system purpose."""
    if status is None:
        tenant = uuid.uuid4()
    else:
        tenant = scene.tenant()
        scene.set_status(tenant, status)
    owner, _ = platform.owner()
    callers: list[Any] = [owner, UserCaller(platform.user()), PROVISIONING, BILLING, BOOTSTRAP]
    platform.clear_audit()
    for caller in callers:
        with pytest.raises(PlatformNotAuthorizedError) as raised:
            _purge(tenant, caller)
        assert raised.value.operation == "tenant.purge_transition"
    if status is not None:
        assert scene.status(tenant) == status.value
    denied = platform.audit(action=_ACTION)
    assert len(denied) == len(callers)
    assert {row["outcome"] for row in denied} == {"denied"}
    assert {row["reason"] for row in denied} == {"not_authorized"}
    assert all(row["target_id"] == str(tenant) for row in denied)


def test_a_service_account_or_a_missing_caller_is_refused_before_anything(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = _deleted_tenant(scene)
    platform.clear_audit()
    with pytest.raises(PlatformNotAuthorizedError):
        _purge(tenant, ServiceAccountCaller(uuid.uuid4(), tenant))
    for not_a_caller in (None, "tenant_purge", uuid.uuid4()):
        with pytest.raises(CallerTypeError):
            _purge(tenant, not_a_caller)
    with pytest.raises(InvalidPlatformRequestError):
        _purge(tenant, TENANT_PURGE, actor_user_id="someone")
    assert scene.status(tenant) == "deleted" and platform.audit() == []


def test_an_operator_holding_every_permission_cannot_purge(
    scene: Scene, platform: PlatformWorld
) -> None:
    """There is no platform permission for purge (ADR-0045 section 4):
    holding all eighteen grants nothing here."""
    tenant = _deleted_tenant(scene)
    everything, _ = platform.operator(list(P))
    with pytest.raises(PlatformNotAuthorizedError):
        _purge(tenant, everything, actor_user_id=everything.user_id)
    assert scene.status(tenant) == "deleted"


def test_without_the_authorization_anyone_purges(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: with the authorization removed, the ordinary user
    the test above refuses purges the tenant."""
    tenant = _deleted_tenant(scene)
    stranger = UserCaller(platform.user())
    with pytest.raises(PlatformNotAuthorizedError):
        _purge(tenant, stranger)
    monkeypatch.setattr(lifecycle_authority, "authorize", lambda *args, **kwargs: None)
    _purge(tenant, stranger)
    assert scene.status(tenant) == "purged"
