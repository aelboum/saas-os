"""The platform hold on one tenant's AI against a real PostgreSQL (ADR-0054
amendment of 2026-11-09; Gap 20b).

Pinned: only `platform.ai_tenant_hold:manage` places or lifts a hold (not a
tenant administrator, not `platform.ai_policy:manage`, not support access,
not a service account or a system purpose); a held tenant is refused before
any adapter call, whatever its policy says, and a policy toggle does not clear
the hold; a hold on one tenant touches no other; release restores service;
every set and release writes a platform and a tenant audit row in one
transaction; an attempt already started completes, while no attempt or
fallback starts after the hold commits, even when the hold commits while an
attempt is starting; the table refuses writes from a tenant-scoped
transaction. FakeAdapter only: no provider, no network.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from ai_inference_world import AIWorld, P, Scene, admin_scalar, attempts, runtime
from lifecycle_callers import PROVISIONING, platform_operator
from saas_os.control_plane.inference import service
from saas_os.control_plane.inference.adapters import (
    AdapterError,
    AdapterResult,
    AdapterUsage,
    ErrorCategory,
    FakeAdapter,
)
from saas_os.control_plane.inference.config import hold as ai_hold
from saas_os.control_plane.inference.config import tenant_policy
from saas_os.control_plane.inference.config.errors import AITenantHoldError
from saas_os.control_plane.inference.config.models import HoldReason
from saas_os.control_plane.inference.errors import InferencePolicyDeniedError
from saas_os.control_plane.inference.types import ContentPart, InferenceRequest, Message
from saas_os.core.authority import ServiceAccountCaller, UserCaller
from saas_os.core.platform_authority import PlatformNotAuthorizedError
from saas_os.core.rbac.service import approve_support_access, create_support_access_request
from saas_os.core.tenancy import TenantStatus, transition_tenant_status
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import tenant_session_scope

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1 FROM control_plane.ai_tenant_holds LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"AI hold table missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch, platform_config_database: None) -> None:
    from saas_os.control_plane.inference.config import service as ai_config

    class _Secrets:
        def get(self, name: str) -> str | None:
            return "placeholder" if name.startswith("AI_TEST_") else None

    monkeypatch.setattr(ai_config, "get_secrets_provider", lambda: _Secrets())
    monkeypatch.setenv("AI_PROVIDER_CREDENTIALS", "AI_TEST_PROVIDER_KEY,AI_TEST_ROTATED")


@pytest.fixture
def world() -> Iterator[AIWorld]:
    w = AIWorld()
    try:
        yield w
    finally:
        w.cleanup()


def _request(scene: Scene) -> InferenceRequest:
    return InferenceRequest(
        alias=scene.alias,
        use_case=scene.use_case.name,
        messages=(Message("user", (ContentPart("text", "tenant_data", text="hello"),)),),
        max_output_tokens=64,
    )


def _ok() -> AdapterResult:
    return AdapterResult(
        text="ok",
        finish_reason="stop",
        usage=AdapterUsage(input_tokens=3, output_tokens=2),
        model="model-1",
        provider_request_id="req-ok",
    )


def _holder(world: AIWorld) -> UserCaller:
    return world.operator(P.AI_TENANT_HOLD_MANAGE)


def _hold_rows(tenant_id: uuid.UUID) -> int:
    return admin_scalar(
        "SELECT count(*) FROM control_plane.ai_tenant_holds WHERE target_tenant_id = :t",
        t=str(tenant_id),
    )


def _tenant_audit(tenant_id: uuid.UUID, action: str) -> int:
    return admin_scalar(
        "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t AND action = :a "
        "AND outcome = 'success'",
        t=str(tenant_id),
        a=action,
    )


def _platform_audit(tenant_id: uuid.UUID, action: str, outcome: str = "success") -> int:
    return admin_scalar(
        "SELECT count(*) FROM core.platform_audit_log WHERE target_tenant_id = :t "
        "AND action = :a AND outcome = :o",
        t=str(tenant_id),
        a=action,
        o=outcome,
    )


# --- default: no hold ------------------------------------------------------------


async def test_without_a_hold_nothing_changes(world: AIWorld) -> None:
    scene = world.scene()
    rt, fake, _ = runtime()
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert result.attempts == 1 and len(fake.calls) == 1
    assert _hold_rows(scene.tenant_id) == 0
    reader = world.operator(P.AI_CONFIG_READ)
    view = ai_hold.read_tenant_ai_hold(scene.tenant_id, caller=reader)
    assert (view.held, view.reason, view.version) == (False, None, 0)


# --- authority ----------------------------------------------------------------------


async def test_only_the_hold_permission_may_set_or_release(world: AIWorld) -> None:
    scene = world.scene()
    policy_only = world.operator(P.AI_POLICY_MANAGE, P.AI_CONFIG_READ, P.TENANT_SUSPEND)
    engineer = world.user()
    approver = world.member(scene.tenant_id, ("support_access_request", "approve"))
    request = create_support_access_request(
        caller=UserCaller(engineer),
        tenant_id=scene.tenant_id,
        reason="hold boundary",
        requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    approve_support_access(caller=approver, tenant_id=scene.tenant_id, request_id=request.id)
    refused: list[object] = [
        scene.manager,  # a tenant administrator holding ai.policy:manage and read
        scene.member,
        policy_only,  # a platform operator without the hold permission
        UserCaller(engineer),  # support access
        ServiceAccountCaller(uuid.uuid4(), scene.tenant_id),
        PROVISIONING,  # a system purpose
        object(),
    ]
    for caller in refused:
        with pytest.raises(Exception) as caught:  # noqa: PT011 -- several refusal types
            ai_hold.set_tenant_ai_hold(scene.tenant_id, reason=HoldReason.SECURITY, caller=caller)
        assert not isinstance(caught.value, AITenantHoldError)
    assert _hold_rows(scene.tenant_id) == 0

    holder = _holder(world)
    ai_hold.set_tenant_ai_hold(scene.tenant_id, reason=HoldReason.SECURITY, caller=holder)
    for caller in refused:
        with pytest.raises(Exception) as caught:  # noqa: PT011
            ai_hold.release_tenant_ai_hold(scene.tenant_id, caller=caller)
        assert not isinstance(caught.value, AITenantHoldError)
    view = ai_hold.read_tenant_ai_hold(scene.tenant_id, caller=world.operator(P.AI_CONFIG_READ))
    assert view.held is True
    # an ordinary operator's refusal is evidenced as a denied platform row
    with pytest.raises(PlatformNotAuthorizedError):
        ai_hold.release_tenant_ai_hold(scene.tenant_id, caller=policy_only)
    assert (
        admin_scalar(
            "SELECT count(*) FROM core.platform_audit_log WHERE actor_user_id = :u "
            "AND action = 'platform.ai_tenant_hold.release' AND outcome = 'denied'",
            u=str(policy_only.user_id),
        )
        >= 1
    )


async def test_a_tenant_administrator_cannot_clear_a_hold_and_a_policy_toggle_does_not(
    world: AIWorld,
) -> None:
    scene = world.scene()
    ai_hold.set_tenant_ai_hold(
        scene.tenant_id, reason=HoldReason.CONTRACTUAL, caller=_holder(world)
    )
    rt, fake, _ = runtime()
    # The tenant's own policy is enabled and fully granted: the hold overrides it.
    with pytest.raises(InferencePolicyDeniedError) as denied:
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert denied.value.reason == "tenant_ai_held"
    # Every tenant-side lever: toggling the policy off and on, re-granting.
    tenant_policy.set_tenant_ai_policy(scene.tenant_id, enabled=False, caller=scene.manager)
    tenant_policy.set_tenant_ai_policy(scene.tenant_id, enabled=True, caller=scene.manager)
    tenant_policy.grant_use_case(
        scene.tenant_id,
        use_case=scene.use_case.name,
        classifications=["none", "tenant_data"],
        caller=scene.manager,
    )
    with pytest.raises(PlatformNotAuthorizedError):
        ai_hold.release_tenant_ai_hold(scene.tenant_id, caller=scene.manager)
    with pytest.raises(InferencePolicyDeniedError) as again:
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert again.value.reason == "tenant_ai_held"
    assert fake.calls == [] and attempts(scene.tenant_id) == []
    assert (
        admin_scalar(
            "SELECT active FROM control_plane.ai_tenant_holds WHERE target_tenant_id = :t",
            t=str(scene.tenant_id),
        )
        is True
    )


async def test_the_tenant_policy_module_never_writes_the_hold() -> None:
    import inspect

    source = inspect.getsource(tenant_policy)
    assert "AITenantHold" not in source and "ai_tenant_holds" not in source


def test_a_tenant_scoped_transaction_cannot_write_the_hold_table(world: AIWorld) -> None:
    scene = world.scene()
    ai_hold.set_tenant_ai_hold(scene.tenant_id, reason=HoldReason.SECURITY, caller=_holder(world))
    with pytest.raises(DBAPIError), tenant_session_scope(scene.tenant_id) as session:
        session.execute(
            text(
                "UPDATE control_plane.ai_tenant_holds SET active = false, released_at = now() "
                "WHERE target_tenant_id = :t"
            ),
            {"t": scene.tenant_id},
        )
    with pytest.raises(DBAPIError), tenant_session_scope(scene.tenant_id) as session:
        session.execute(
            text(
                "INSERT INTO control_plane.ai_tenant_holds "
                "(id, target_tenant_id, reason, active, held_at) "
                "VALUES (gen_random_uuid(), :t, 'security', true, now())"
            ),
            {"t": uuid.uuid4()},
        )
    with pytest.raises(DBAPIError), tenant_session_scope(scene.tenant_id) as session:
        session.execute(
            text("DELETE FROM control_plane.ai_tenant_holds WHERE target_tenant_id = :t"),
            {"t": scene.tenant_id},
        )
    with tenant_session_scope(scene.tenant_id) as session:  # reading is allowed
        assert (
            session.execute(
                text(
                    "SELECT active FROM control_plane.ai_tenant_holds WHERE target_tenant_id = :t"
                ),
                {"t": scene.tenant_id},
            ).scalar_one()
            is True
        )
    assert _hold_rows(scene.tenant_id) == 1


# --- enforcement and recovery -------------------------------------------------------


async def test_a_held_tenant_is_refused_before_any_adapter_call_and_release_restores(
    world: AIWorld,
) -> None:
    scene = world.scene()
    holder = _holder(world)
    rt, fake, gate = runtime()
    view = ai_hold.set_tenant_ai_hold(scene.tenant_id, reason=HoldReason.SPENDING, caller=holder)
    assert (view.held, view.reason, view.version) == (True, "spending", 1)
    for _ in range(2):
        with pytest.raises(InferencePolicyDeniedError) as denied:
            await service.run_inference(
                scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
            )
        assert denied.value.reason == "tenant_ai_held" and denied.value.category == "policy_denied"
    assert fake.calls == [] and attempts(scene.tenant_id) == []
    assert gate.admitted == 0  # refused before admission
    # the refusal is evidenced in the tenant's own audit trail, reason code only
    assert (
        admin_scalar(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t "
            "AND outcome = 'denied' AND metadata::text LIKE '%tenant_ai_held%'",
            t=str(scene.tenant_id),
        )
        == 2
    )

    released = ai_hold.release_tenant_ai_hold(scene.tenant_id, caller=holder)
    assert (released.held, released.reason, released.version) == (False, "spending", 2)
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert result.attempts == 1 and len(fake.calls) == 1

    again = ai_hold.set_tenant_ai_hold(scene.tenant_id, reason=HoldReason.OPERATOR, caller=holder)
    assert (again.held, again.reason, again.version) == (True, "operator", 3)


async def test_repeats_are_typed_errors_that_change_and_audit_nothing(world: AIWorld) -> None:
    scene = world.scene()
    holder = _holder(world)
    with pytest.raises(AITenantHoldError) as not_held:
        ai_hold.release_tenant_ai_hold(scene.tenant_id, caller=holder)
    assert not_held.value.reason == "not_held" and _hold_rows(scene.tenant_id) == 0
    ai_hold.set_tenant_ai_hold(scene.tenant_id, reason=HoldReason.SECURITY, caller=holder)
    with pytest.raises(AITenantHoldError) as already:
        ai_hold.set_tenant_ai_hold(scene.tenant_id, reason=HoldReason.OPERATOR, caller=holder)
    assert already.value.reason == "already_held"
    assert _tenant_audit(scene.tenant_id, "ai.policy.hold") == 1
    assert _platform_audit(scene.tenant_id, "platform.ai_tenant_hold.set") == 1
    ai_hold.release_tenant_ai_hold(scene.tenant_id, caller=holder)
    with pytest.raises(AITenantHoldError):
        ai_hold.release_tenant_ai_hold(scene.tenant_id, caller=holder)
    assert _tenant_audit(scene.tenant_id, "ai.policy.release_hold") == 1


@pytest.mark.parametrize("reason", ["", "free text", "SECURITY", None, 7, "security "])
def test_only_the_closed_reason_set_is_accepted(world: AIWorld, reason: Any) -> None:
    scene = world.scene()
    with pytest.raises(AITenantHoldError) as refused:
        ai_hold.set_tenant_ai_hold(scene.tenant_id, reason=reason, caller=_holder(world))
    assert refused.value.reason == "invalid_reason" and _hold_rows(scene.tenant_id) == 0


def test_the_reason_set_is_exactly_the_four_reviewed_values() -> None:
    assert {r.value for r in HoldReason} == {"security", "contractual", "spending", "operator"}


# --- isolation ----------------------------------------------------------------------------


async def test_a_hold_on_one_tenant_does_not_touch_another(world: AIWorld) -> None:
    a, b = world.scene(), world.scene()
    ai_hold.set_tenant_ai_hold(a.tenant_id, reason=HoldReason.SECURITY, caller=_holder(world))
    rt, fake, _ = runtime()
    with pytest.raises(InferencePolicyDeniedError):
        await service.run_inference(
            a.member, tenant_id=a.tenant_id, request=_request(a), runtime=rt
        )
    result = await service.run_inference(
        b.member, tenant_id=b.tenant_id, request=_request(b), runtime=rt
    )
    assert result.attempts == 1 and len(fake.calls) == 1
    assert _hold_rows(b.tenant_id) == 0
    assert _tenant_audit(b.tenant_id, "ai.policy.hold") == 0


def test_an_unknown_tenant_is_refused_and_a_closed_one_can_still_be_wound_down(
    world: AIWorld,
) -> None:
    holder = _holder(world)
    with pytest.raises(AITenantHoldError) as unknown:
        ai_hold.set_tenant_ai_hold(uuid.uuid4(), reason=HoldReason.SECURITY, caller=holder)
    assert unknown.value.reason == "tenant_unavailable"
    # Releasing a tenant that does not exist reads like releasing one that is
    # not held: the same refusal, so the call does not tell them apart.
    known = world.tenant()
    refusals = []
    for tenant_id in (uuid.uuid4(), known):
        with pytest.raises(AITenantHoldError) as refused:
            ai_hold.release_tenant_ai_hold(tenant_id, caller=holder)
        refusals.append(str(refused.value))
    assert refusals[0] == refusals[1] == "tenant AI hold refused: not_held"
    reader = world.operator(P.AI_CONFIG_READ)
    unknown_view = ai_hold.read_tenant_ai_hold(uuid.uuid4(), caller=reader)
    known_view = ai_hold.read_tenant_ai_hold(known, caller=reader)
    assert (unknown_view.held, unknown_view.reason) == (known_view.held, known_view.reason)
    assert (unknown_view.held, unknown_view.reason) == (False, None)
    # A hold only reduces authority: a closed tenant stays windable-down.
    closed = world.tenant()
    transition_tenant_status(closed, TenantStatus.DELETED, caller=platform_operator())
    assert ai_hold.set_tenant_ai_hold(closed, reason=HoldReason.OPERATOR, caller=holder).held
    assert not ai_hold.release_tenant_ai_hold(closed, caller=holder).held


# --- evidence --------------------------------------------------------------------------------


def test_set_and_release_write_a_platform_and_a_tenant_audit_row(world: AIWorld) -> None:
    scene = world.scene()
    holder = _holder(world)
    ai_hold.set_tenant_ai_hold(scene.tenant_id, reason=HoldReason.CONTRACTUAL, caller=holder)
    ai_hold.release_tenant_ai_hold(scene.tenant_id, caller=holder)
    for action, change in (
        ("ai.policy.hold", "hold"),
        ("ai.policy.release_hold", "release_hold"),
    ):
        assert _tenant_audit(scene.tenant_id, action) == 1
        metadata = admin_scalar(
            "SELECT metadata FROM core.audit_log WHERE tenant_id = :t AND action = :a",
            t=str(scene.tenant_id),
            a=action,
        )
        assert metadata == {"change": change, "reason": "contractual", "platform": True}
        actor = admin_scalar(
            "SELECT actor_user_id FROM core.audit_log WHERE tenant_id = :t AND action = :a",
            t=str(scene.tenant_id),
            a=action,
        )
        assert actor == holder.user_id  # the existing replay convention: the operator
    for action, change in (
        ("platform.ai_tenant_hold.set", "hold"),
        ("platform.ai_tenant_hold.release", "release_hold"),
    ):
        assert _platform_audit(scene.tenant_id, action) == 1
        metadata = admin_scalar(
            "SELECT metadata FROM core.platform_audit_log WHERE target_tenant_id = :t "
            "AND action = :a",
            t=str(scene.tenant_id),
            a=action,
        )
        assert metadata == {"change": change, "reason": "contractual"}
    assert (
        admin_scalar(
            "SELECT reason FROM core.platform_audit_log WHERE target_tenant_id = :t "
            "AND action = 'platform.ai_tenant_hold.set'",
            t=str(scene.tenant_id),
        )
        == "contractual"
    )


def test_a_failed_tenant_audit_row_after_the_commit_leaves_the_hold_in_force_and_is_logged(
    world: AIWorld, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The platform-configuration role cannot write a tenant's audit log
    (ADR-0056 D2), so the tenant's row follows the commit. A failure there
    does not undo or hide the hold: the platform trail is complete and the
    gap is logged, closed codes only."""
    scene = world.scene()

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("tenant audit unavailable")

    monkeypatch.setattr(ai_hold, "record_in_transaction", broken)
    with caplog.at_level("ERROR"):
        view = ai_hold.set_tenant_ai_hold(
            scene.tenant_id, reason=HoldReason.SECURITY, caller=_holder(world)
        )
    assert view.held is True and _hold_rows(scene.tenant_id) == 1
    assert _platform_audit(scene.tenant_id, "platform.ai_tenant_hold.set") == 1
    assert _tenant_audit(scene.tenant_id, "ai.policy.hold") == 0
    assert "ai_tenant_hold_tenant_audit_failed" in caplog.text
    assert "tenant audit unavailable" not in caplog.text


def test_a_failed_platform_audit_row_rolls_the_hold_and_the_tenant_row_back(
    world: AIWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    from saas_os.core.platform_authority import changes

    scene = world.scene()

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("platform audit unavailable")

    monkeypatch.setattr(changes, "record_platform_event_in_transaction", broken)
    with pytest.raises(RuntimeError):
        ai_hold.set_tenant_ai_hold(
            scene.tenant_id, reason=HoldReason.SECURITY, caller=_holder(world)
        )
    assert _hold_rows(scene.tenant_id) == 0
    assert _tenant_audit(scene.tenant_id, "ai.policy.hold") == 0


# --- in-flight behaviour ---------------------------------------------------------------------


class _HoldingAdapter(FakeAdapter):
    """Places the hold while its first attempt is in flight (the attempt's
    `started` row has committed; the provider call is under way)."""

    def __init__(self, script: list, tenant_id: uuid.UUID, holder: UserCaller) -> None:
        super().__init__(script)
        self._tenant_id = tenant_id
        self._holder = holder
        self._placed = False

    async def complete(self, request: Any, **kwargs: Any) -> AdapterResult:
        if not self._placed:
            self._placed = True
            await asyncio.to_thread(
                ai_hold.set_tenant_ai_hold,
                self._tenant_id,
                reason=HoldReason.SECURITY,
                caller=self._holder,
            )
        return await super().complete(request, **kwargs)


async def test_an_attempt_already_started_completes_and_settles(world: AIWorld) -> None:
    scene = world.scene()
    adapter = _HoldingAdapter([_ok()], scene.tenant_id, _holder(world))
    rt, _, _ = runtime(adapter=adapter)
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    assert result.attempts == 1 and result.output[0].text == "ok"
    assert [r["state"] for r in attempts(scene.tenant_id)] == ["succeeded"]
    # ... and the next request is refused
    with pytest.raises(InferencePolicyDeniedError, match="tenant_ai_held"):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert len(adapter.calls) == 1


@pytest.mark.parametrize("destinations", [1, 2])
async def test_no_retry_or_fallback_starts_after_the_hold_commits(
    world: AIWorld, destinations: int
) -> None:
    scene = world.scene(destinations=destinations)
    overloaded = AdapterError(ErrorCategory.PROVIDER_OVERLOADED, possibly_accepted=False)
    adapter = _HoldingAdapter([overloaded, _ok(), _ok()], scene.tenant_id, _holder(world))
    rt, _, gate = runtime(adapter=adapter)
    with pytest.raises(InferencePolicyDeniedError) as denied:
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert denied.value.reason == "tenant_ai_held"
    assert len(adapter.calls) == 1  # no second attempt, not a retry, not a fallback
    assert [(r["state"], r["error_category"]) for r in attempts(scene.tenant_id)] == [
        ("failed", "provider_overloaded")
    ]
    assert gate.released == gate.admitted == 1


# --- concurrency around the commit -----------------------------------------------------


async def test_an_attempt_that_starts_while_the_hold_commits_waits_and_is_refused(
    world: AIWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hold's transaction has written its row but not committed, and holds
    the tenant's gate. A request that resolved just before (so it still sees
    no hold) must not start its attempt until the hold commits, and then
    sees it. Without the gate it would start an attempt after the hold was
    already in force."""
    scene = world.scene()
    holder = _holder(world)
    rt, fake, _ = runtime()
    inside, proceed = threading.Event(), threading.Event()
    original = ai_hold._flush  # noqa: SLF001

    def slow(session: Any) -> None:
        original(session)
        inside.set()
        assert proceed.wait(30)

    monkeypatch.setattr(ai_hold, "_flush", slow)
    placed: list[object] = []
    setter = threading.Thread(
        target=lambda: placed.append(
            ai_hold.set_tenant_ai_hold(scene.tenant_id, reason=HoldReason.SECURITY, caller=holder)
        )
    )
    setter.start()
    assert inside.wait(30)
    outcome: list[BaseException | object] = []

    def request_thread() -> None:
        try:
            outcome.append(
                asyncio.run(
                    service.run_inference(
                        scene.member,
                        tenant_id=scene.tenant_id,
                        request=_request(scene),
                        runtime=rt,
                    )
                )
            )
        except BaseException as exc:  # noqa: BLE001
            outcome.append(exc)

    requester = threading.Thread(target=request_thread)
    requester.start()
    time.sleep(2.0)
    assert requester.is_alive(), "the attempt must wait for the hold's commit"
    assert fake.calls == [] and attempts(scene.tenant_id) == []
    proceed.set()
    setter.join(30)
    requester.join(30)
    assert not setter.is_alive() and not requester.is_alive() and placed
    (result,) = outcome
    assert isinstance(result, InferencePolicyDeniedError) and result.reason == "tenant_ai_held"
    assert fake.calls == [] and attempts(scene.tenant_id) == []


def test_a_hold_waits_for_an_attempt_that_is_starting(world: AIWorld) -> None:
    """The converse: an attempt-start transaction holds the gate shared; the
    hold waits for it and then commits, so the attempt is in flight."""
    scene = world.scene()
    holder = _holder(world)
    done = threading.Event()
    placed: list[object] = []

    def place() -> None:
        placed.append(
            ai_hold.set_tenant_ai_hold(scene.tenant_id, reason=HoldReason.SECURITY, caller=holder)
        )
        done.set()

    with tenant_session_scope(scene.tenant_id) as session:
        ai_hold.lock_hold_gate_shared(session, scene.tenant_id)
        assert ai_hold.tenant_ai_held(session, scene.tenant_id) is False
        thread = threading.Thread(target=place)
        thread.start()
        assert not done.wait(1.5), "the hold must wait for the starting attempt"
    thread.join(30)
    assert done.is_set() and placed
    with tenant_session_scope(scene.tenant_id) as session:
        assert ai_hold.tenant_ai_held(session, scene.tenant_id) is True
