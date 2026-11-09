"""Tenant model eligibility, ranking and grant-time validation against a real
PostgreSQL (ADR-0054 amendment of 2026-11-09; Gap 20a).

Pinned: `list_eligible_models` reports, for each catalogue model, the closed
reason codes `run_inference` would refuse it for and agrees with the real
resolver (a model reported eligible is used, a model reported blocked is not),
keeps the four families distinct, and never returns an endpoint or a
credential reference; a tenant's rank only orders models the tenant granted
and an alias lists, never makes an ineligible one eligible; duplicate, negative
and out-of-alias ranks are refused with a typed error and no write; a grant
the evaluator would never allow is refused with its reason codes while
disabling and pre-existing grants are untouched; every rank change writes a
same-transaction audit row; ranks are tenant-isolated. FakeAdapter only: no
provider, no network.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from ai_inference_world import REASON, SECRET_NAME, AIWorld, P, Scene, admin_scalar, runtime
from saas_os.control_plane.inference import service
from saas_os.control_plane.inference.adapters import AdapterResult, AdapterUsage
from saas_os.control_plane.inference.capabilities import Capability
from saas_os.control_plane.inference.config import hold as ai_hold
from saas_os.control_plane.inference.config import service as ai_config
from saas_os.control_plane.inference.config import tenant_policy
from saas_os.control_plane.inference.config.errors import AITenantPolicyError
from saas_os.control_plane.inference.config.models import HoldReason
from saas_os.control_plane.inference.eligibility import REASON_FAMILIES, list_eligible_models
from saas_os.control_plane.inference.errors import InferencePolicyDeniedError
from saas_os.control_plane.inference.types import ContentPart, InferenceRequest, Message
from saas_os.control_plane.inference.use_cases import UseCase, register_use_case
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

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
            conn.execute(
                text(
                    "SELECT preference_rank FROM control_plane.ai_tenant_destination_grants LIMIT 1"
                )
            )
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"preference_rank column missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch, platform_config_database: None) -> None:
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


async def _used(scene: Scene) -> str:
    rt, _, _ = runtime([_ok()])
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    return result.provider_key


def _view(scene: Scene, *, alias: bool = True) -> dict:
    rt, _, _ = runtime()
    views = list_eligible_models(
        scene.tenant_id,
        use_case=scene.use_case.name,
        caller=scene.manager,
        alias=scene.alias if alias else None,
        adapter_capabilities=rt.adapter_capabilities(),
    )
    return {v.provider_key: v for v in views}


def _rank(scene: Scene, destination, rank, *, caller=None):  # type: ignore[no-untyped-def]
    return tenant_policy.set_destination_rank(
        scene.tenant_id,
        use_case=scene.use_case.name,
        provider_key=destination.provider_key,
        model_id=destination.model_id,
        rank=rank,
        caller=caller or scene.manager,
    )


def _audit(tenant_id: uuid.UUID, action: str, outcome: str = "success") -> int:
    return admin_scalar(
        "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t AND action = :a AND outcome = :o",
        t=str(tenant_id),
        a=action,
        o=outcome,
    )


def _stored_rank(scene: Scene, destination) -> int | None:  # type: ignore[no-untyped-def]
    return admin_scalar(
        "SELECT preference_rank FROM control_plane.ai_tenant_destination_grants "
        "WHERE tenant_id = :t AND model_ref = :m AND use_case = :u",
        t=str(scene.tenant_id),
        m=str(destination.model_ref),
        u=scene.use_case.name,
    )


# --- ranking ----------------------------------------------------------------------


async def test_without_ranks_the_alias_order_is_kept(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    assert await _used(scene) == scene.destinations[0].provider_key


async def test_a_rank_reorders_and_clearing_it_restores_alias_order(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    first, second = scene.destinations
    _rank(scene, second, 0)
    _rank(scene, first, 1)
    assert await _used(scene) == second.provider_key
    _rank(scene, second, None)
    # `first` is the only ranked grant now, so it precedes the unranked one.
    assert await _used(scene) == first.provider_key
    _rank(scene, first, None)
    assert await _used(scene) == first.provider_key  # all null: alias order again
    assert _stored_rank(scene, first) is None and _stored_rank(scene, second) is None


async def test_a_ranked_grant_precedes_every_unranked_one(world: AIWorld) -> None:
    scene = world.scene(destinations=3)
    _rank(scene, scene.destinations[2], 7)
    assert await _used(scene) == scene.destinations[2].provider_key


async def test_a_rank_never_makes_an_ineligible_model_eligible(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    first, second = scene.destinations
    _rank(scene, first, 0)
    ai_config.set_provider_status(
        key=first.provider_key, status="disabled", caller=scene.operator, reason=REASON
    )
    assert await _used(scene) == second.provider_key
    assert _view(scene)[first.provider_key].blocked_by == ("provider_disabled",)


async def test_a_model_outside_every_alias_cannot_be_ranked(world: AIWorld) -> None:
    scene = world.scene()
    outsider = world.destination(scene.operator)
    tenant_policy.grant_destination(
        scene.tenant_id,
        use_case=scene.use_case.name,
        provider_key=outsider.provider_key,
        model_id=outsider.model_id,
        classifications=["none", "tenant_data"],
        caller=scene.manager,
    )
    with pytest.raises(AITenantPolicyError) as excinfo:
        _rank(scene, outsider, 0)
    assert excinfo.value.reason == "model_not_in_alias"
    assert _stored_rank(scene, outsider) is None


async def test_only_a_granted_model_can_be_ranked(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    other_use_case = register_use_case(
        UseCase(name=f"{scene.use_case.name}-b", max_classification="tenant_data")
    )
    with pytest.raises(AITenantPolicyError) as excinfo:
        tenant_policy.set_destination_rank(
            scene.tenant_id,
            use_case=other_use_case.name,
            provider_key=scene.destinations[0].provider_key,
            model_id=scene.destinations[0].model_id,
            rank=0,
            caller=scene.manager,
        )
    assert excinfo.value.reason == "destination_not_granted"


@pytest.mark.parametrize("bad", [-1, 32768, True, "1", 1.5])
async def test_an_invalid_rank_is_refused_and_nothing_is_written(
    world: AIWorld, bad: object
) -> None:
    scene = world.scene(destinations=2)
    before = _audit(scene.tenant_id, "ai.policy.set_rank")
    with pytest.raises(AITenantPolicyError) as excinfo:
        _rank(scene, scene.destinations[0], bad)
    assert excinfo.value.reason == "invalid_rank"
    assert _stored_rank(scene, scene.destinations[0]) is None
    assert _audit(scene.tenant_id, "ai.policy.set_rank") == before


async def test_a_duplicate_rank_is_refused_and_the_other_grant_is_unchanged(
    world: AIWorld,
) -> None:
    scene = world.scene(destinations=2)
    first, second = scene.destinations
    _rank(scene, first, 3)
    with pytest.raises(AITenantPolicyError) as excinfo:
        _rank(scene, second, 3)
    assert excinfo.value.reason == "duplicate_rank"
    assert _stored_rank(scene, first) == 3 and _stored_rank(scene, second) is None
    _rank(scene, first, 3)  # re-setting its own rank is not a duplicate


async def test_the_database_refuses_a_duplicate_or_negative_rank(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    _rank(scene, scene.destinations[0], 4)
    params = {"t": str(scene.tenant_id), "m": str(scene.destinations[1].model_ref)}
    engine = build_engine(get_migrations_database_config())
    try:
        for value, constraint in (
            (4, "ux_ai_tenant_destination_grants_rank"),
            (-1, "ck_ai_tenant_destination_grants_rank"),
        ):
            with pytest.raises(Exception, match=constraint):  # noqa: PT011
                with engine.begin() as conn:
                    conn.execute(
                        text(
                            "UPDATE control_plane.ai_tenant_destination_grants "
                            f"SET preference_rank = {value} "
                            "WHERE tenant_id = :t AND model_ref = :m"
                        ),
                        params,
                    )
    finally:
        engine.dispose()


async def test_ranking_needs_ai_policy_manage_and_a_refusal_is_audited(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    reader = world.member(scene.tenant_id, ("ai.policy", "read"))
    with pytest.raises(AuthorityNotAuthorizedError):
        _rank(scene, scene.destinations[0], 0, caller=reader)
    assert _stored_rank(scene, scene.destinations[0]) is None
    assert _audit(scene.tenant_id, "ai.policy.set_rank", "denied") == 1
    with pytest.raises(AuthorityNotAuthorizedError):
        _rank(scene, scene.destinations[0], 0, caller=scene.operator)
    assert _stored_rank(scene, scene.destinations[0]) is None


async def test_a_rank_change_writes_a_same_transaction_audit_row(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    _rank(scene, scene.destinations[0], 2)
    assert _audit(scene.tenant_id, "ai.policy.set_rank") == 1
    metadata = admin_scalar(
        "SELECT metadata FROM core.audit_log "
        "WHERE tenant_id = :t AND action = 'ai.policy.set_rank'",
        t=str(scene.tenant_id),
    )
    assert metadata["rank"] == 2 and metadata["change"] == "set_rank"
    assert SECRET_NAME not in str(metadata)


async def test_ranks_are_tenant_isolated(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    other = world.tenant()
    other_manager = world.member(other, ("ai.policy", "manage"), ("ai.policy", "read"))
    tenant_policy.set_tenant_ai_policy(other, enabled=True, caller=other_manager)
    tenant_policy.grant_use_case(
        other, use_case=scene.use_case.name, classifications=["none"], caller=other_manager
    )
    tenant_policy.grant_destination(
        other,
        use_case=scene.use_case.name,
        provider_key=scene.destinations[1].provider_key,
        model_id=scene.destinations[1].model_id,
        classifications=["none"],
        caller=other_manager,
    )
    _rank(scene, scene.destinations[1], 0)
    theirs = tenant_policy.read_tenant_ai_policy(other, caller=other_manager)
    assert [d.preference_rank for d in theirs.destinations] == [None]
    mine = tenant_policy.read_tenant_ai_policy(scene.tenant_id, caller=scene.manager)
    assert [d.preference_rank for d in mine.destinations if d.preference_rank is not None] == [0]
    with pytest.raises(AuthorityNotAuthorizedError):
        tenant_policy.set_destination_rank(
            other,
            use_case=scene.use_case.name,
            provider_key=scene.destinations[1].provider_key,
            model_id=scene.destinations[1].model_id,
            rank=0,
            caller=scene.manager,
        )


async def test_regranting_a_destination_keeps_its_rank(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    _rank(scene, scene.destinations[1], 0)
    view = tenant_policy.grant_destination(
        scene.tenant_id,
        use_case=scene.use_case.name,
        provider_key=scene.destinations[1].provider_key,
        model_id=scene.destinations[1].model_id,
        classifications=["none"],
        caller=scene.manager,
    )
    assert view.preference_rank == 0 and _stored_rank(scene, scene.destinations[1]) == 0


# --- grant-time validation ------------------------------------------------------


def _grant(scene: Scene, destination, *, enabled: bool = True, classes=("none",)):  # type: ignore[no-untyped-def]
    return tenant_policy.grant_destination(
        scene.tenant_id,
        use_case=scene.use_case.name,
        provider_key=destination.provider_key,
        model_id=destination.model_id,
        classifications=list(classes),
        enabled=enabled,
        caller=scene.manager,
    )


def _grant_rows(scene: Scene, destination) -> int:  # type: ignore[no-untyped-def]
    return admin_scalar(
        "SELECT count(*) FROM control_plane.ai_tenant_destination_grants "
        "WHERE tenant_id = :t AND model_ref = :m",
        t=str(scene.tenant_id),
        m=str(destination.model_ref),
    )


async def test_a_disabled_model_cannot_be_granted(world: AIWorld) -> None:
    scene = world.scene()
    extra = world.destination(scene.operator)
    ai_config.set_model_lifecycle(
        provider_key=extra.provider_key,
        model_id=extra.model_id,
        lifecycle="disabled",
        caller=scene.operator,
        reason=REASON,
    )
    with pytest.raises(AITenantPolicyError) as excinfo:
        _grant(scene, extra)
    assert excinfo.value.reason == "destination_not_eligible"
    assert excinfo.value.blocked_by == ("model_disabled",)
    assert _grant_rows(scene, extra) == 0


async def test_a_classification_installation_policy_denies_cannot_be_granted(
    world: AIWorld,
) -> None:
    scene = world.scene()
    narrow = world.destination(scene.operator, allow=("none",))
    _grant(scene, narrow, classes=("none",))  # allowed
    with pytest.raises(AITenantPolicyError) as excinfo:
        _grant(scene, narrow, classes=("none", "tenant_data"))
    assert excinfo.value.blocked_by == ("destination_policy_denied",)
    stored = admin_scalar(
        "SELECT classifications FROM control_plane.ai_tenant_destination_grants "
        "WHERE tenant_id = :t AND model_ref = :m",
        t=str(scene.tenant_id),
        m=str(narrow.model_ref),
    )
    assert stored == ["none"]  # the refused update changed nothing


async def test_a_grant_that_violates_the_tenants_own_requirements_is_refused(
    world: AIWorld,
) -> None:
    scene = world.scene()
    extra = world.destination(scene.operator)
    ai_config.set_provider_data_handling(
        key=extra.provider_key,
        residency=["eu"],
        retention_days=90,
        training_use=True,
        caller=scene.operator,
        reason=REASON,
    )
    tenant_policy.set_tenant_ai_preferences(
        scene.tenant_id,
        allowed_residency=["us"],
        max_retention_days=30,
        exclude_training_use=True,
        caller=scene.manager,
    )
    with pytest.raises(AITenantPolicyError) as excinfo:
        _grant(scene, extra)
    assert set(excinfo.value.blocked_by) == {"residency", "retention", "training_use"}
    assert _grant_rows(scene, extra) == 0


async def test_disabling_an_ineligible_grant_is_always_allowed(world: AIWorld) -> None:
    scene = world.scene()
    first = scene.destinations[0]
    ai_config.set_model_lifecycle(
        provider_key=first.provider_key,
        model_id=first.model_id,
        lifecycle="disabled",
        caller=scene.operator,
        reason=REASON,
    )
    assert _grant(scene, first, enabled=False).enabled is False


async def test_existing_grants_survive_later_requirements_and_call_time_decides(
    world: AIWorld,
) -> None:
    scene = world.scene(destinations=2)
    tenant_policy.set_tenant_ai_preferences(
        scene.tenant_id, allowed_residency=["us"], caller=scene.manager
    )
    mine = tenant_policy.read_tenant_ai_policy(scene.tenant_id, caller=scene.manager)
    assert len(mine.destinations) == 2 and all(d.enabled for d in mine.destinations)
    assert all(v.blocked_by == ("residency",) for v in _view(scene).values() if v.granted)
    with pytest.raises(InferencePolicyDeniedError) as excinfo:
        await _used(scene)
    assert excinfo.value.reason == "no_eligible_destination"


# --- the eligibility view ---------------------------------------------------------


async def test_the_view_agrees_with_the_resolver_when_everything_is_allowed(
    world: AIWorld,
) -> None:
    scene = world.scene(destinations=2)
    shown = _view(scene)
    for destination in scene.destinations:
        entry = shown[destination.provider_key]
        assert entry.eligible and entry.granted
        assert entry.blocked_by == () and entry.families == ()
    assert await _used(scene) in shown


@pytest.mark.parametrize(
    ("code", "family"),
    [
        ("provider_disabled", "disabled"),
        ("credential_unbound", "disabled"),
        ("model_disabled", "disabled"),
        ("destination_policy_denied", "blocked"),
        ("residency", "blocked"),
        ("retention", "blocked"),
        ("training_use", "blocked"),
        ("not_granted", "blocked"),
    ],
)
async def test_each_model_fault_is_reported_with_exactly_its_code_and_the_resolver_agrees(
    world: AIWorld, code: str, family: str
) -> None:
    scene = world.scene(destinations=2)
    faulty, healthy = scene.destinations
    op = scene.operator
    if code == "provider_disabled":
        ai_config.set_provider_status(
            key=faulty.provider_key, status="disabled", caller=op, reason=REASON
        )
    elif code == "credential_unbound":
        ai_config.set_provider_credential_ref(
            key=faulty.provider_key, credential_ref="AI_TEST_ROTATED", caller=op, reason=REASON
        )
    elif code == "model_disabled":
        ai_config.set_model_lifecycle(
            provider_key=faulty.provider_key,
            model_id=faulty.model_id,
            lifecycle="disabled",
            caller=op,
            reason=REASON,
        )
    elif code == "destination_policy_denied":
        ai_config.set_destination_policy(
            provider_key=faulty.provider_key,
            classification="tenant_data",
            allowed=False,
            caller=op,
            reason=REASON,
        )
    elif code in {"residency", "retention", "training_use"}:
        # `healthy` declares enough to meet any requirement; `faulty` declares nothing.
        ai_config.set_provider_data_handling(
            key=healthy.provider_key,
            residency=["us"],
            retention_days=1,
            training_use=False,
            caller=op,
            reason=REASON,
        )
        tenant_policy.set_tenant_ai_preferences(
            scene.tenant_id,
            allowed_residency=["us"] if code == "residency" else (),
            max_retention_days=30 if code == "retention" else None,
            exclude_training_use=code == "training_use",
            caller=scene.manager,
        )
    elif code == "not_granted":
        _grant(scene, faulty, enabled=False)
    shown = _view(scene)
    assert shown[healthy.provider_key].eligible
    entry = shown[faulty.provider_key]
    assert not entry.eligible
    assert entry.blocked_by == (code,)
    assert entry.families == (family,)
    assert REASON_FAMILIES[code] == family
    assert await _used(scene) == healthy.provider_key


async def test_a_model_the_alias_does_not_list_is_unavailable(world: AIWorld) -> None:
    scene = world.scene()
    outsider = world.destination(scene.operator)
    entry = _view(scene)[outsider.provider_key]
    assert entry.blocked_by == ("not_in_alias", "not_granted")
    assert entry.families == ("blocked", "unavailable")
    assert _view(scene, alias=False)[outsider.provider_key].blocked_by == ("not_granted",)


async def test_a_missing_capability_is_reported_and_the_resolver_agrees(world: AIWorld) -> None:
    operator = world.operator(P.AI_PROVIDER_MANAGE, P.AI_POLICY_MANAGE)
    lacking = world.destination(operator, capabilities=("text_input", "text_output"))
    capable = world.destination(operator)
    alias = f"alias-{uuid.uuid4().hex[:8]}"
    world.aliases.append(alias)
    ai_config.set_alias(
        alias=alias,
        candidates=[
            (lacking.provider_key, lacking.model_id),
            (capable.provider_key, capable.model_id),
        ],
        caller=operator,
        reason=REASON,
    )
    use_case = register_use_case(
        UseCase(
            name=f"uc-{uuid.uuid4().hex[:8]}",
            max_classification="tenant_data",
            required_capabilities=frozenset({Capability.TEMPERATURE}),
        )
    )
    tenant_id = world.tenant()
    manager = world.member(tenant_id, ("ai.policy", "manage"), ("ai.policy", "read"))
    member = world.member(tenant_id, ("ai.inference", "run"))
    tenant_policy.set_tenant_ai_policy(tenant_id, enabled=True, caller=manager)
    tenant_policy.grant_use_case(
        tenant_id, use_case=use_case.name, classifications=["none", "tenant_data"], caller=manager
    )
    for destination in (lacking, capable):
        tenant_policy.grant_destination(
            tenant_id,
            use_case=use_case.name,
            provider_key=destination.provider_key,
            model_id=destination.model_id,
            classifications=["none", "tenant_data"],
            caller=manager,
        )
    rt, _, _ = runtime([_ok()])
    shown = {
        v.provider_key: v
        for v in list_eligible_models(
            tenant_id,
            use_case=use_case.name,
            caller=manager,
            alias=alias,
            adapter_capabilities=rt.adapter_capabilities(),
        )
    }
    assert shown[lacking.provider_key].blocked_by == ("capability",)
    assert shown[capable.provider_key].eligible
    result = await service.run_inference(
        member,
        tenant_id=tenant_id,
        request=InferenceRequest(
            alias=alias,
            use_case=use_case.name,
            messages=(Message("user", (ContentPart("text", "tenant_data", text="hello"),)),),
            max_output_tokens=64,
            temperature=0.5,
        ),
        runtime=rt,
    )
    assert result.provider_key == capable.provider_key


async def test_tenant_level_states_stay_distinct_and_the_resolver_agrees(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    # suspended: the platform hold.
    holder = world.operator(P.AI_TENANT_HOLD_MANAGE)
    ai_hold.set_tenant_ai_hold(scene.tenant_id, reason=HoldReason.SECURITY, caller=holder)
    held = _view(scene)
    assert all(v.blocked_by == ("tenant_ai_held",) for v in held.values() if v.granted)
    assert all(v.families == ("suspended",) for v in held.values() if v.granted)
    with pytest.raises(InferencePolicyDeniedError) as excinfo:
        await _used(scene)
    assert excinfo.value.reason == "tenant_ai_held"
    ai_hold.release_tenant_ai_hold(scene.tenant_id, caller=holder)
    # disabled: the tenant switch.
    tenant_policy.set_tenant_ai_policy(scene.tenant_id, enabled=False, caller=scene.manager)
    off = _view(scene)
    assert all(v.blocked_by == ("tenant_ai_disabled",) for v in off.values() if v.granted)
    assert all(v.families == ("disabled",) for v in off.values() if v.granted)
    with pytest.raises(InferencePolicyDeniedError):
        await _used(scene)
    tenant_policy.set_tenant_ai_policy(scene.tenant_id, enabled=True, caller=scene.manager)
    # blocked: the use case is not granted.
    tenant_policy.grant_use_case(
        scene.tenant_id,
        use_case=scene.use_case.name,
        classifications=["none"],
        enabled=False,
        caller=scene.manager,
    )
    ungranted = _view(scene)
    assert all(v.blocked_by == ("use_case_not_granted",) for v in ungranted.values() if v.granted)
    with pytest.raises(InferencePolicyDeniedError):
        await _used(scene)


async def test_an_unknown_alias_is_unavailable(world: AIWorld) -> None:
    scene = world.scene()
    rt, _, _ = runtime()
    views = list_eligible_models(
        scene.tenant_id,
        use_case=scene.use_case.name,
        caller=scene.manager,
        alias="no-such-alias",
        adapter_capabilities=rt.adapter_capabilities(),
    )
    mine = [v for v in views if v.provider_key == scene.destinations[0].provider_key]
    assert mine and mine[0].blocked_by == ("alias_unavailable", "not_in_alias")
    assert mine[0].families == ("unavailable",)


async def test_the_view_returns_no_endpoint_credential_or_secret(world: AIWorld) -> None:
    scene = world.scene()
    entry = _view(scene)[scene.destinations[0].provider_key]
    rendered = repr(entry)
    assert "api.example.com" not in rendered and SECRET_NAME not in rendered
    assert entry.credential_bound is True
    assert not hasattr(entry, "base_url") and not hasattr(entry, "credential_ref")


async def test_the_view_requires_ai_policy_read_and_a_tenant_user_or_service_caller(
    world: AIWorld,
) -> None:
    scene = world.scene()
    caps = runtime()[0].adapter_capabilities()
    stranger = world.member(world.tenant(), ("ai.policy", "read"))
    for caller in (scene.member, scene.operator, stranger):
        # member: ai.inference:run only; operator: platform, not tenant, authority;
        # stranger: ai.policy:read in a different tenant.
        with pytest.raises(AuthorityNotAuthorizedError):
            list_eligible_models(
                scene.tenant_id,
                use_case=scene.use_case.name,
                caller=caller,
                adapter_capabilities=caps,
            )


async def test_the_view_refuses_an_unknown_use_case_or_classification_and_writes_nothing(
    world: AIWorld,
) -> None:
    scene = world.scene()
    caps = runtime()[0].adapter_capabilities()
    count = "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t"
    before = admin_scalar(count, t=str(scene.tenant_id))
    with pytest.raises(AITenantPolicyError) as unknown:
        list_eligible_models(
            scene.tenant_id,
            use_case="not-registered",
            caller=scene.manager,
            adapter_capabilities=caps,
        )
    assert unknown.value.reason == "use_case_not_registered"
    with pytest.raises(AITenantPolicyError) as bad:
        list_eligible_models(
            scene.tenant_id,
            use_case=scene.use_case.name,
            caller=scene.manager,
            classification="top-secret",
            adapter_capabilities=caps,
        )
    assert bad.value.reason == "invalid_classifications"
    list_eligible_models(
        scene.tenant_id,
        use_case=scene.use_case.name,
        caller=scene.manager,
        adapter_capabilities=caps,
    )
    assert admin_scalar(count, t=str(scene.tenant_id)) == before
