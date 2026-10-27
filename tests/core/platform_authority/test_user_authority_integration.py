"""User deactivation and credential revocation against a real PostgreSQL
(ADR-0045 Phase C, section 11): `revoke_user_sessions`,
`revoke_user_api_keys`, `deactivate_user`, `reactivate_user`, the scan
ceiling, and the operator-login audit event.

The races are in `test_user_deactivation_race_integration.py`; negative
controls in `test_phase_c_negative_controls_integration.py`.

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from phase_c_helpers import BILLING, PROVISIONING, REASON, TENANT_PURGE, P, Scene
from platform_helpers import BOOTSTRAP, PlatformWorld

import saas_os.core.identity.user_authority as user_authority
from saas_os.core.api_keys import (
    RevokedApiKeyError,
    create_api_key,
    rotate_api_key,
    validate_api_key,
)
from saas_os.core.authority import CallerTypeError, ServiceAccountCaller, UserCaller
from saas_os.core.identity import (
    DeactivationScanConfigurationError,
    create_service_account,
    get_deactivation_scan_config,
    issue_session,
    revoke_user_api_keys,
    revoke_user_sessions,
    validate_session,
)
from saas_os.core.identity.errors import (
    InactiveUserError,
    InvalidUserStateError,
    LastTenantAdministratorError,
    SessionRevokedError,
)
from saas_os.core.identity.user_authority import deactivate_user, reactivate_user
from saas_os.core.platform_authority import (
    DeactivationScanLimitError,
    InvalidPlatformRequestError,
    LastPlatformOwnerError,
    PlatformNotAuthorizedError,
    PlatformSelfTargetError,
    PlatformSubjectNotFoundError,
    platform_can,
)
from saas_os.core.rbac import can
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.tenancy import TenantStatus
from saas_os.infra.db import session_scope

pytestmark = pytest.mark.integration

OPERATIONS = {
    "deactivate": (deactivate_user, P.USER_DEACTIVATE, "platform.user.deactivate"),
    "reactivate": (reactivate_user, P.USER_REACTIVATE, "platform.user.reactivate"),
    "sessions": (revoke_user_sessions, P.SESSION_REVOKE, "platform.session.revoke"),
    "api_keys": (revoke_user_api_keys, P.API_KEY_REVOKE, "platform.api_key.revoke"),
}


@pytest.fixture(autouse=True)
def _default_ceiling(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.delenv("PLATFORM_DEACTIVATION_MAX_TENANTS", raising=False)
    get_deactivation_scan_config.cache_clear()
    yield
    get_deactivation_scan_config.cache_clear()


def _target(scene: Scene, platform: PlatformWorld) -> tuple[uuid.UUID, uuid.UUID]:
    """An ordinary member of a tenant that has another administrator.
    Returns `(user_id, tenant_id)`."""
    tenant = scene.tenant(active=True)
    scene.admin(tenant)
    user_id, _ = scene.member(tenant)
    return user_id, tenant


# --- callers and permission isolation ------------------------------------------------


@pytest.mark.parametrize("name", list(OPERATIONS))
def test_callers_other_than_the_permission_holder_are_refused(
    scene: Scene, platform: PlatformWorld, name: str
) -> None:
    operation, permission, action = OPERATIONS[name]
    user_id, tenant = _target(scene, platform)
    scene.session_for(user_id)
    scene.api_key(tenant, user_id)
    if name == "reactivate":
        platform.set_user_active(user_id, False)

    for bad in (None, "operator", object()):
        with pytest.raises(CallerTypeError):
            operation(user_id, caller=bad, reason=REASON)
    administrator, _ = scene.admin(tenant)
    everything_else, _ = platform.operator([p for p in P if p is not permission])
    refused: list[Any] = [
        ServiceAccountCaller(service_account_id=uuid.uuid4(), tenant_id=tenant),
        UserCaller(platform.user()),
        administrator,
        everything_else,
        PROVISIONING,
        TENANT_PURGE,
        BILLING,
        BOOTSTRAP,
    ]
    for caller in refused:
        with pytest.raises(PlatformNotAuthorizedError):
            operation(user_id, caller=caller, reason=REASON)
    assert scene.user_is_active(user_id) is (name != "reactivate")
    assert scene.live_sessions(user_id) == 1 and scene.live_keys(user_id) == 1
    assert platform.audit(action=action, outcome="success") == []
    denied = platform.audit(action=action, outcome="denied")
    assert {row["reason"] for row in denied} == {"not_authorized"}
    # A service account is refused and logged, not recorded (no actor column).
    assert len(denied) == len(refused) - 1

    holder, _ = platform.operator([permission])
    operation(user_id, caller=holder, reason=REASON)
    assert len(platform.audit(action=action, outcome="success")) == 1


@pytest.mark.parametrize("name", list(OPERATIONS))
def test_a_reason_and_a_real_user_are_required(
    scene: Scene, platform: PlatformWorld, name: str
) -> None:
    operation, permission, action = OPERATIONS[name]
    holder, _ = platform.operator([permission])
    user_id, _ = _target(scene, platform)
    for reason in ("", "   ", None, "x" * 501, "line\nbreak"):
        with pytest.raises(InvalidPlatformRequestError):
            operation(user_id, caller=holder, reason=reason)  # type: ignore[arg-type]
    with pytest.raises(InvalidPlatformRequestError):
        operation("not-a-uuid", caller=holder, reason=REASON)  # type: ignore[arg-type]
    unknown = uuid.uuid4()
    with pytest.raises(PlatformSubjectNotFoundError):
        operation(unknown, caller=holder, reason=REASON)
    denied = platform.audit(action=action, outcome="denied")
    assert [(row["reason"], row["target_id"]) for row in denied] == [
        ("user_not_found", str(unknown))
    ]
    assert platform.audit(action=action, outcome="success") == []


# --- session revocation ----------------------------------------------------------


def test_revoking_sessions_ends_every_session_and_changes_nothing_else(
    scene: Scene, platform: PlatformWorld
) -> None:
    user_id, tenant = _target(scene, platform)
    tokens = [scene.session_for(user_id) for _ in range(3)]
    _, raw_key = scene.api_key(tenant, user_id)
    other = platform.user()
    other_token = scene.session_for(other)
    holder, _ = platform.operator([P.SESSION_REVOKE])
    platform.clear_audit()

    assert revoke_user_sessions(user_id, caller=holder, reason=REASON) == 3
    for token in tokens:
        with pytest.raises(SessionRevokedError):
            validate_session(token)
    assert validate_session(other_token).user_id == other
    assert scene.user_is_active(user_id) and scene.live_keys(user_id) == 1
    assert validate_api_key(raw_key).user_id == user_id  # keys untouched
    assert validate_session(scene.session_for(user_id)).user_id == user_id  # may log in again

    rows = platform.audit(action="platform.session.revoke", outcome="success")
    assert len(rows) == 1 and rows[0]["actor_user_id"] == holder.user_id
    assert rows[0]["target_type"] == "user" and rows[0]["target_id"] == str(user_id)
    assert rows[0]["reason"] == REASON and rows[0]["metadata"] == {"sessions_revoked": 3}


def test_session_revocation_succeeds_for_a_last_owner_and_a_last_administrator(
    scene: Scene, platform: PlatformWorld
) -> None:
    owner, _ = platform.owner()
    tenant = scene.tenant(active=True)
    sole_admin, _ = scene.admin(tenant)
    scene.session_for(owner.user_id)
    scene.session_for(sole_admin.user_id)
    # A caller may revoke their own sessions: a logout everywhere.
    assert revoke_user_sessions(owner.user_id, caller=owner, reason=REASON) == 1
    assert revoke_user_sessions(sole_admin.user_id, caller=owner, reason=REASON) == 1
    assert platform.owner_count() == 1
    assert scene.has_administrator(tenant)


# --- API-key revocation -----------------------------------------------------------


def test_revoking_api_keys_revokes_every_user_owned_key_in_every_tenant(
    scene: Scene, platform: PlatformWorld
) -> None:
    user_id, tenant_a = _target(scene, platform)
    tenant_b = scene.tenant(active=True)
    scene.join(tenant_b, user_id)
    keys_a = [scene.api_key(tenant_a, user_id) for _ in range(2)]
    key_b = scene.api_key(tenant_b, user_id)
    bystander, _ = scene.member(tenant_a)
    _, bystander_raw = scene.api_key(tenant_a, bystander)
    token = scene.session_for(user_id)
    holder, _ = platform.operator([P.API_KEY_REVOKE])
    platform.clear_audit()

    assert revoke_user_api_keys(user_id, caller=holder, reason=REASON) == 3
    for _key_id, raw in (*keys_a, key_b):
        with pytest.raises(RevokedApiKeyError):
            validate_api_key(raw)
    assert validate_api_key(bystander_raw).user_id == bystander
    assert scene.user_is_active(user_id)
    assert validate_session(token).user_id == user_id  # sessions untouched

    rows = platform.audit(action="platform.api_key.revoke", outcome="success")
    assert len(rows) == 1 and rows[0]["actor_user_id"] == holder.user_id
    assert rows[0]["metadata"] == {"api_keys_revoked": 3, "tenants_affected": 2}
    assert rows[0]["target_tenant_id"] is None  # no key id, no tenant id
    flat = str(rows[0])
    for key_id, _raw in (*keys_a, key_b):
        assert str(key_id) not in flat
    assert str(tenant_a) not in flat and str(tenant_b) not in flat

    # Each tenant sees, in its own trail, who revoked which key.
    for tenant, expected in ((tenant_a, {k for k, _ in keys_a}), (tenant_b, {key_b[0]})):
        own = [
            row
            for row in scene.tenant_audit(tenant, "api_key.revoke")
            if row["actor_user_id"] == holder.user_id
        ]
        assert {uuid.UUID(row["resource_id"]) for row in own} == expected
        assert all(
            row["metadata"] == {"owner_user_id": str(user_id), "platform": True} for row in own
        )

    # Idempotent: nothing left to revoke; still authorized and recorded.
    assert revoke_user_api_keys(user_id, caller=holder, reason=REASON) == 0


def test_a_key_revoked_by_the_platform_cannot_be_rotated_back_into_a_live_one(
    scene: Scene, platform: PlatformWorld
) -> None:
    """Revocation is permanent: neither the (still active) owner nor a tenant
    administrator allowed to rotate keys turns a key `revoke_user_api_keys()`
    revoked into a new live key by rotating it."""
    user_id, tenant = _target(scene, platform)
    administrator, _ = scene.admin(tenant, extra=[("api_key", "rotate")])
    key_id, _ = scene.api_key(tenant, user_id)
    holder, _ = platform.operator([P.API_KEY_REVOKE])
    assert revoke_user_api_keys(user_id, caller=holder, reason=REASON) == 1
    assert scene.user_is_active(user_id)

    for caller in (UserCaller(user_id), administrator):
        with pytest.raises(RevokedApiKeyError):
            rotate_api_key(tenant, key_id, caller=caller)
    assert scene.live_keys(user_id) == 0
    assert scene.tenant_audit(tenant, "api_key.rotate") == []


def test_api_key_revocation_leaves_service_account_keys_and_needs_no_invariant(
    scene: Scene, platform: PlatformWorld
) -> None:
    from saas_os.core.api_keys import create_service_account_api_key

    tenant = scene.tenant(active=True)
    sole_admin, _ = scene.admin(
        tenant, extra=[("service_account", "create"), ("api_key", "create")]
    )
    account = create_service_account(tenant, "bot", caller=sole_admin)
    _, machine_raw = create_service_account_api_key(
        caller=sole_admin, tenant_id=tenant, service_account_id=account.id, name="bot-key"
    )
    _, own_raw = scene.api_key(tenant, sole_admin.user_id)
    holder, _ = platform.operator([P.API_KEY_REVOKE])
    # A last tenant administrator's keys can be revoked.
    assert revoke_user_api_keys(sole_admin.user_id, caller=holder, reason=REASON) == 1
    with pytest.raises(RevokedApiKeyError):
        validate_api_key(own_raw)
    assert validate_api_key(machine_raw).service_account_id == account.id
    assert scene.has_administrator(tenant)
    # The target may be the caller: it removes no authority.
    assert revoke_user_api_keys(holder.user_id, caller=holder, reason=REASON) == 0


def test_a_failure_after_the_update_leaves_every_key_live(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    import saas_os.core.api_keys.service as api_keys_service

    user_id, tenant = _target(scene, platform)
    _, raw = scene.api_key(tenant, user_id)
    holder, _ = platform.operator([P.API_KEY_REVOKE])
    platform.clear_audit()

    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("forced failure after the update")

    monkeypatch.setattr(api_keys_service, "record_platform_key_revocations", boom)
    with pytest.raises(RuntimeError):
        revoke_user_api_keys(user_id, caller=holder, reason=REASON)
    assert validate_api_key(raw).user_id == user_id
    assert platform.audit(action="platform.api_key.revoke", outcome="success") == []
    failures = platform.audit(action="platform.api_key.revoke", outcome="failure")
    assert [row["reason"] for row in failures] == ["error"]


def test_a_key_in_a_closed_tenant_is_revoked_and_its_tenant_row_is_written(
    scene: Scene, platform: PlatformWorld
) -> None:
    """Open question for Phase C: `core.audit_log` accepts a row for a
    DELETED tenant, so the per-key tenant evidence is not omitted."""
    user_id, tenant = _target(scene, platform)
    key_id, _ = scene.api_key(tenant, user_id)
    scene.set_status(tenant, TenantStatus.DELETED)
    holder, _ = platform.operator([P.API_KEY_REVOKE])
    assert revoke_user_api_keys(user_id, caller=holder, reason=REASON) == 1
    own = [
        r for r in scene.tenant_audit(tenant, "api_key.revoke") if r["resource_id"] == str(key_id)
    ]
    assert len(own) == 1 and own[0]["actor_user_id"] == holder.user_id


# --- deactivation ------------------------------------------------------------------


def test_deactivation_revokes_sessions_and_keys_and_refuses_the_user_everywhere(
    scene: Scene, platform: PlatformWorld
) -> None:
    user_id, tenant_a = _target(scene, platform)
    tenant_b = scene.tenant(active=True)
    scene.admin(tenant_b)
    scene.join(tenant_b, user_id)
    tokens = [scene.session_for(user_id) for _ in range(2)]
    key_a = scene.api_key(tenant_a, user_id)
    key_b = scene.api_key(tenant_b, user_id)
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    platform.clear_audit()

    result = deactivate_user(user_id, caller=holder, reason=REASON)
    assert (result.sessions_revoked, result.api_keys_revoked) == (2, 2)
    assert not scene.user_is_active(user_id)
    for token in tokens:
        with pytest.raises(SessionRevokedError):  # refused on the next request
            validate_session(token)
    for _key_id, raw in (key_a, key_b):
        with pytest.raises(RevokedApiKeyError):
            validate_api_key(raw)
    with pytest.raises(InactiveUserError):
        issue_session(user_id)
    with pytest.raises(AuthorityNotAuthorizedError):
        create_api_key(tenant_a, "after", caller=UserCaller(user_id))

    rows = platform.audit(action="platform.user.deactivate", outcome="success")
    assert len(rows) == 1 and rows[0]["actor_user_id"] == holder.user_id
    metadata = rows[0]["metadata"]
    assert metadata["sessions_revoked"] == 2 and metadata["api_keys_revoked"] == 2
    assert metadata["tenants_affected"] == 2 and metadata["memberships_guarded"] == 2
    assert metadata["tenants_visited_first_pass"] == metadata["tenants_visited_second_pass"]
    assert metadata["tenants_visited_first_pass"] >= 2
    for tenant, (key_id, _raw) in ((tenant_a, key_a), (tenant_b, key_b)):
        own = [
            r
            for r in scene.tenant_audit(tenant, "api_key.revoke")
            if r["resource_id"] == str(key_id)
        ]
        assert len(own) == 1 and own[0]["actor_user_id"] == holder.user_id

    with pytest.raises(InvalidUserStateError):
        deactivate_user(user_id, caller=holder, reason=REASON)


def test_a_caller_may_not_deactivate_themselves(scene: Scene, platform: PlatformWorld) -> None:
    platform.owner()
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    with pytest.raises(PlatformSelfTargetError):
        deactivate_user(holder.user_id, caller=holder, reason=REASON)
    assert scene.user_is_active(holder.user_id)
    denied = platform.audit(action="platform.user.deactivate", outcome="denied")
    assert [row["reason"] for row in denied] == ["self_target"]


def test_deactivating_the_sole_administrator_of_a_tenant_is_refused_and_names_it(
    scene: Scene, platform: PlatformWorld
) -> None:
    """Blocking race test (4) of ADR-0045 Phase C, and the consequence
    stated in section 11c."""
    tenant = scene.tenant(active=True)
    sole_admin, _ = scene.admin(tenant)
    token = scene.session_for(sole_admin.user_id)
    _, raw = scene.api_key(tenant, sole_admin.user_id)
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    with pytest.raises(LastTenantAdministratorError) as refused:
        deactivate_user(sole_admin.user_id, caller=holder, reason=REASON)
    assert refused.value.tenant_id == tenant
    assert scene.user_is_active(sole_admin.user_id) and scene.has_administrator(tenant)
    assert validate_session(token).user_id == sole_admin.user_id  # nothing was revoked
    assert validate_api_key(raw).user_id == sole_admin.user_id
    denied = platform.audit(action="platform.user.deactivate", outcome="denied")
    assert [row["reason"] for row in denied] == ["last_tenant_administrator"]
    assert denied[0]["metadata"] == {"tenant_id": str(tenant)}
    assert platform.audit(action="platform.user.deactivate", outcome="success") == []
    # With a second administrator the same deactivation succeeds.
    scene.admin(tenant)
    deactivate_user(sole_admin.user_id, caller=holder, reason=REASON)
    assert not scene.user_is_active(sole_admin.user_id) and scene.has_administrator(tenant)


def test_deactivating_the_last_platform_owner_is_refused(
    scene: Scene, platform: PlatformWorld
) -> None:
    owner, _ = platform.owner()
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    token = scene.session_for(owner.user_id)
    with pytest.raises(LastPlatformOwnerError):
        deactivate_user(owner.user_id, caller=holder, reason=REASON)
    assert scene.user_is_active(owner.user_id) and platform.owner_count() == 1
    assert validate_session(token).user_id == owner.user_id
    denied = platform.audit(action="platform.user.deactivate", outcome="denied")
    assert [row["reason"] for row in denied] == ["last_platform_owner"]
    # With a second owner it succeeds, and the deactivated owner's operator
    # row and grants are untouched: ownership is lost through `is_active`.
    _, second = platform.owner()
    deactivate_user(owner.user_id, caller=holder, reason=REASON)
    assert platform.owner_count() == 1
    assert not platform_can(user_id=owner.user_id, permission=P.AUTHORITY_MANAGE)
    assert platform.operator_status(second) == "active"


def test_a_user_who_is_last_owner_and_last_administrator_is_refused_by_one_of_the_two(
    scene: Scene, platform: PlatformWorld
) -> None:
    owner, _ = platform.owner()
    tenant = scene.tenant(active=True)
    scene.make_admin(tenant, owner.user_id)
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    with pytest.raises((LastTenantAdministratorError, LastPlatformOwnerError)):
        deactivate_user(owner.user_id, caller=holder, reason=REASON)
    assert scene.user_is_active(owner.user_id)
    assert platform.owner_count() == 1 and scene.has_administrator(tenant)


# --- reactivation --------------------------------------------------------------------


def test_reactivation_restores_no_credential(scene: Scene, platform: PlatformWorld) -> None:
    user_id, tenant = _target(scene, platform)
    token = scene.session_for(user_id)
    _, raw = scene.api_key(tenant, user_id)
    operator, _ = platform.operator([P.USER_DEACTIVATE, P.USER_REACTIVATE])
    deactivate_user(user_id, caller=operator, reason=REASON)
    # A session row inserted behind the deactivation (what a racing login
    # would leave if issuance did not lock the user row), and a key likewise.
    platform.execute(
        "INSERT INTO core.sessions (id, user_id, token_hash, expires_at) "
        "VALUES (gen_random_uuid(), :u, :h, now() + interval '1 hour')",
        {"u": user_id, "h": uuid.uuid4().hex},
    )
    platform.execute(
        "UPDATE core.api_keys SET revoked_at = NULL WHERE user_id = :u", {"u": user_id}
    )
    platform.clear_audit()

    result = reactivate_user(user_id, caller=operator, reason=REASON)
    assert (result.sessions_revoked, result.api_keys_revoked) == (1, 1)
    assert scene.user_is_active(user_id)
    assert scene.live_sessions(user_id) == 0 and scene.live_keys(user_id) == 0
    with pytest.raises(SessionRevokedError):
        validate_session(token)
    with pytest.raises(RevokedApiKeyError):
        validate_api_key(raw)
    rows = platform.audit(action="platform.user.reactivate", outcome="success")
    assert len(rows) == 1 and rows[0]["metadata"]["api_keys_revoked"] == 1
    # The user logs in again and is issued a new key.
    assert validate_session(scene.session_for(user_id)).user_id == user_id
    assert validate_api_key(scene.api_key(tenant, user_id)[1]).user_id == user_id
    with pytest.raises(InvalidUserStateError):
        reactivate_user(user_id, caller=operator, reason=REASON)


def test_reactivating_a_deactivated_owner_restores_ownership_without_a_grant_change(
    scene: Scene, platform: PlatformWorld
) -> None:
    first, _ = platform.owner()
    second, _ = platform.owner()
    operator, _ = platform.operator([P.USER_DEACTIVATE, P.USER_REACTIVATE])
    deactivate_user(first.user_id, caller=operator, reason=REASON)
    assert platform.owner_count() == 1
    grants_before = platform.scalar("SELECT count(*) FROM core.platform_grants")
    reactivate_user(first.user_id, caller=operator, reason=REASON)
    assert platform.owner_count() == 2
    assert platform.scalar("SELECT count(*) FROM core.platform_grants") == grants_before
    assert platform_can(user_id=first.user_id, permission=P.AUTHORITY_MANAGE)
    assert second.user_id != first.user_id


def test_rotating_the_key_of_an_inactive_owner_is_refused(
    scene: Scene, platform: PlatformWorld
) -> None:
    tenant = scene.tenant(active=True)
    administrator, _ = scene.admin(tenant, extra=[("api_key", "rotate")])
    user_id, _ = scene.member(tenant)
    key_id, _ = scene.api_key(tenant, user_id)
    rotated, _ = rotate_api_key(tenant, key_id, caller=administrator)  # active owner: allowed
    platform.set_user_active(user_id, False)
    with pytest.raises(AuthorityNotAuthorizedError):
        rotate_api_key(tenant, rotated.id, caller=administrator)
    assert scene.live_keys(user_id) == 1  # no new key was issued for the inactive owner


# --- the scan ceiling (ruling R1) ----------------------------------------------------


def _set_ceiling(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("PLATFORM_DEACTIVATION_MAX_TENANTS", value)
    get_deactivation_scan_config.cache_clear()


def test_a_registry_at_the_ceiling_proceeds_and_one_above_is_refused(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    user_id, tenant = _target(scene, platform)
    token = scene.session_for(user_id)
    _, raw = scene.api_key(tenant, user_id)
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    scene.tenant()  # at least two tenants, so that "one below" is a valid ceiling
    population = scene.unpurged_tenants()
    platform.clear_audit()

    _set_ceiling(monkeypatch, str(population - 1))
    with pytest.raises(DeactivationScanLimitError) as refused:
        deactivate_user(user_id, caller=holder, reason=REASON)
    assert refused.value.ceiling == population - 1
    assert scene.user_is_active(user_id)  # the user stays active
    assert validate_session(token).user_id == user_id  # no credential revoked
    assert validate_api_key(raw).user_id == user_id
    denied = platform.audit(action="platform.user.deactivate", outcome="denied")
    assert len(denied) == 1 and denied[0]["reason"] == "registry_scan_limit"
    assert denied[0]["metadata"] == {"ceiling": population - 1}  # no tenant count

    _set_ceiling(monkeypatch, str(population))
    deactivate_user(user_id, caller=holder, reason=REASON)
    assert not scene.user_is_active(user_id)


def test_tenants_created_between_the_two_scans_can_pass_the_ceiling(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    user_id, _ = _target(scene, platform)
    scene.session_for(user_id)
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    _set_ceiling(monkeypatch, str(scene.unpurged_tenants()))
    real = user_authority._scan_active_memberships
    calls = {"n": 0}

    def scan_then_grow(*args: Any, **kwargs: Any) -> Any:
        result = real(*args, **kwargs)
        calls["n"] += 1
        if calls["n"] == 1:
            scene.tenant()  # committed by another connection, after the first scan
        return result

    monkeypatch.setattr(user_authority, "_scan_active_memberships", scan_then_grow)
    with pytest.raises(DeactivationScanLimitError):
        deactivate_user(user_id, caller=holder, reason=REASON)
    assert calls["n"] == 1  # the second scan raised: never a partial result
    assert scene.user_is_active(user_id) and scene.live_sessions(user_id) == 1


def test_a_caller_without_the_permission_causes_no_scan(
    scene: Scene, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    user_id, _ = _target(scene, platform)
    scanned: list[int] = []
    monkeypatch.setattr(
        user_authority,
        "_scan_active_memberships",
        lambda *a, **k: scanned.append(1) or (frozenset(), 0),
    )
    monkeypatch.setattr(
        user_authority, "count_unpurged_tenants", lambda *a, **k: scanned.append(1) or 0
    )
    wrong, _ = platform.operator([P.SESSION_REVOKE, P.USER_REACTIVATE])
    for caller in (UserCaller(platform.user()), wrong):
        with pytest.raises(PlatformNotAuthorizedError):
            deactivate_user(user_id, caller=caller, reason=REASON)
    assert scanned == []


@pytest.mark.parametrize("value", ["0", "-5", "ten", "1.5", ""])
def test_an_invalid_ceiling_is_a_configuration_error(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    _set_ceiling(monkeypatch, value)
    with pytest.raises(DeactivationScanConfigurationError):
        get_deactivation_scan_config()


def test_an_unset_ceiling_defaults_to_ten_thousand(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PLATFORM_DEACTIVATION_MAX_TENANTS", raising=False)
    get_deactivation_scan_config.cache_clear()
    assert get_deactivation_scan_config().max_tenants == 10_000


# --- operator logins -----------------------------------------------------------------


def test_a_session_issued_to_an_enrolled_operator_is_recorded(
    scene: Scene, platform: PlatformWorld
) -> None:
    operator, operator_id = platform.operator([P.TENANT_READ])
    ordinary = platform.user()
    platform.clear_audit()
    record, _ = issue_session(operator.user_id)
    issue_session(ordinary)
    rows = platform.audit(action="platform.operator.session_issued")
    assert len(rows) == 1
    assert rows[0]["actor_type"] == "user" and rows[0]["actor_user_id"] == operator.user_id
    assert rows[0]["target_type"] == "session" and rows[0]["target_id"] == str(record.id)
    assert rows[0]["metadata"] == {"operator_id": str(operator_id)}


def test_no_decision_survives_a_deactivation(scene: Scene, platform: PlatformWorld) -> None:
    """A request already past authentication re-evaluates `can()` and
    `platform_can()` under lock and is refused."""
    tenant = scene.tenant(active=True)
    scene.admin(tenant)
    administrator, _ = scene.admin(tenant)
    operator, _ = platform.operator([P.TENANT_READ])
    holder, _ = platform.operator([P.USER_DEACTIVATE])
    assert can(
        actor_id=administrator.user_id,
        tenant_id=tenant,
        action="create",
        resource="membership_role",
    )
    deactivate_user(administrator.user_id, caller=holder, reason=REASON)
    deactivate_user(operator.user_id, caller=holder, reason=REASON)
    assert not can(
        actor_id=administrator.user_id,
        tenant_id=tenant,
        action="create",
        resource="membership_role",
    )
    with session_scope() as session:
        assert not platform_can(user_id=operator.user_id, permission=P.TENANT_READ, session=session)
