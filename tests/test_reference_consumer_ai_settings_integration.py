"""A product turns AI on for its tenant through the public interface only
(Gap 20 decision 1 (H3); issue #285; ADR-0054 section 3a, amendment of
2026-11-17).

The platform side (provider, model, alias, installation destination policy,
the provider's data-handling declaration, the plan) is set up here with the
internal configuration functions, as `saas-os-operator ai-*` would. The
tenant side is `reference_consumer.ai_settings`, which imports
`saas_os.inference.settings` and nothing else of SaaS OS, followed by one
`run_inference` call through `reference_consumer.inference`; the provider is
the scripted fake adapter, everything else is real.

Also pinned, through the public functions: AI is off for a new tenant;
every change needs its permission, and a refusal writes a `denied` row and
changes nothing; support access never changes a setting; a user of one
tenant cannot change another; a model installation policy does not allow,
or one that fails the tenant's own requirements, cannot be granted; a
platform hold refuses the call although every tenant setting allows it; the
tenant's own budget cap and its status.
"""

from __future__ import annotations

import ast
import sys
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

_REFERENCE_CONSUMER_ROOT = Path(__file__).resolve().parents[1] / "examples" / "reference-consumer"
if str(_REFERENCE_CONSUMER_ROOT) not in sys.path:
    sys.path.insert(0, str(_REFERENCE_CONSUMER_ROOT))

from reference_consumer import ai_settings as consumer_settings  # noqa: E402
from reference_consumer import inference as consumer  # noqa: E402

import saas_os.core.identity.models  # noqa: E402, F401  (registers core.users for audit FKs)
from ai_inference_world import (  # noqa: E402
    REASON,
    AIWorld,
    Destination,
    P,
    admin_scalar,
    attempts,
    unique,
)
from saas_os.control_plane.inference import service  # noqa: E402
from saas_os.control_plane.inference.adapters import FakeAdapter, OpaqueCredential  # noqa: E402
from saas_os.control_plane.inference.config import hold as ai_hold  # noqa: E402
from saas_os.control_plane.inference.config import service as ai_config  # noqa: E402
from saas_os.control_plane.inference.config.models import HoldReason  # noqa: E402
from saas_os.core.authority import ServiceAccountCaller, UserCaller  # noqa: E402
from saas_os.core.billing.provider import FakeBillingProvider  # noqa: E402
from saas_os.core.billing.service import create_plan, subscribe  # noqa: E402
from saas_os.core.rbac import AuthorityNotAuthorizedError  # noqa: E402
from saas_os.core.rbac.service import (  # noqa: E402
    approve_support_access,
    create_support_access_request,
)
from saas_os.inference import InferencePolicyDeniedError, settings  # noqa: E402
from saas_os.infra.db.config import get_database_config, get_migrations_database_config  # noqa: E402
from saas_os.infra.db.engine import build_engine, get_engine  # noqa: E402

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_MANAGER_PERMISSIONS = (
    ("ai.policy", "manage"),
    ("ai.policy", "read"),
    ("ai.budget", "manage"),
    ("ai.usage", "read"),
)
_POLICY_ACTIONS = (
    "ai.policy.set",
    "ai.policy.grant_use_case",
    "ai.policy.set_preferences",
    "ai.policy.grant_destination",
    "ai.policy.set_rank",
)


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
    except (OperationalError, ProgrammingError) as exc:
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
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
def plans() -> Iterator[list[str]]:
    keys: list[str] = []
    yield keys
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM core.billing_plans WHERE key = ANY(:k)"), {"k": keys})
    finally:
        engine.dispose()


@pytest.fixture
def world(plans: list[str]) -> Iterator[AIWorld]:
    w = AIWorld()
    try:
        yield w
    finally:
        engine = build_engine(get_migrations_database_config())
        try:
            with engine.begin() as conn:
                for table in (
                    "billing_provider_refs",
                    "billing_subscriptions",
                    "idempotency_records",
                ):
                    conn.execute(
                        text(f"DELETE FROM core.{table} WHERE tenant_id = ANY(:t)"),
                        {"t": [str(t) for t in w.tenant_ids]},
                    )
        finally:
            engine.dispose()
        w.cleanup()


@pytest.fixture
def fake_provider(monkeypatch: pytest.MonkeyPatch) -> FakeAdapter:
    fake = FakeAdapter()
    runtime = service.default_runtime()
    monkeypatch.setattr(runtime, "adapters", {"openai_chat_completions": fake})
    monkeypatch.setattr(runtime, "egress", lambda eligible: None)
    monkeypatch.setattr(runtime, "credential", lambda name: OpaqueCredential("test-credential"))
    return fake


# --- the platform side (operator commands) -----------------------------------------


class _Catalogue:
    def __init__(self, world: AIWorld, *, allow: tuple[str, ...] = ("none", "tenant_data")):
        self.operator = world.operator(P.AI_PROVIDER_MANAGE, P.AI_POLICY_MANAGE)
        self.model = self.add_model(world, training_use=False, allow=allow)
        self.alias = unique("alias")
        world.aliases.append(self.alias)
        ai_config.set_alias(
            alias=self.alias,
            candidates=[(self.model.provider_key, self.model.model_id)],
            caller=self.operator,
            reason=REASON,
        )
        consumer.register_inference_use_cases()

    def add_model(
        self, world: AIWorld, *, training_use: bool, allow: tuple[str, ...]
    ) -> Destination:
        target = world.destination(self.operator, allow=allow)
        ai_config.set_provider_data_handling(
            key=target.provider_key,
            residency=(),
            retention_days=None,
            training_use=training_use,
            caller=self.operator,
            reason=REASON,
        )
        return target


def _entitle(plans: list[str], tenant_id: uuid.UUID) -> None:
    key = f"ai-plan-{uuid.uuid4().hex[:8]}"
    create_plan(key, "AI plan", entitlements={"ai.inference": True})
    plans.append(key)
    subscribe(tenant_id, key, provider=FakeBillingProvider())


def _audit(tenant_id: uuid.UUID, action: str, outcome: str) -> int:
    return admin_scalar(
        "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t AND action = :a AND outcome = :o",
        t=str(tenant_id),
        a=action,
        o=outcome,
    )


def _setting_rows(tenant_id: uuid.UUID) -> int:
    return admin_scalar(
        "SELECT (SELECT count(*) FROM control_plane.ai_tenant_policies WHERE tenant_id = :t)"
        " + (SELECT count(*) FROM control_plane.ai_tenant_use_case_grants WHERE tenant_id = :t)"
        " + (SELECT count(*) FROM control_plane.ai_tenant_destination_grants"
        "    WHERE tenant_id = :t)"
        " + (SELECT count(*) FROM control_plane.ai_tenant_preferences WHERE tenant_id = :t)"
        " + (SELECT count(*) FROM control_plane.ai_tenant_budgets WHERE tenant_id = :t)",
        t=str(tenant_id),
    )


def _support_engineer(world: AIWorld, tenant_id: uuid.UUID) -> UserCaller:
    approver = world.member(tenant_id, ("support_access_request", "approve"))
    engineer = world.user()
    request = create_support_access_request(
        caller=UserCaller(engineer),
        tenant_id=tenant_id,
        reason="issue 285 support boundary",
        requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    approve_support_access(caller=approver, tenant_id=tenant_id, request_id=request.id)
    return UserCaller(engineer)


def _every_write(
    caller: object, tenant_id: uuid.UUID, model: Destination
) -> list[tuple[str, Callable[[], object]]]:
    """Each public write, as a thunk, with the audit action its refusal records."""
    use_case = consumer.SUMMARIZE_NOTE.name
    return [
        (
            "ai.policy.set",
            lambda: settings.set_tenant_ai_policy(tenant_id, enabled=True, caller=caller),
        ),
        (
            "ai.policy.grant_use_case",
            lambda: settings.grant_use_case(
                tenant_id, use_case=use_case, classifications=["none"], caller=caller
            ),
        ),
        (
            "ai.policy.grant_destination",
            lambda: settings.grant_destination(
                tenant_id,
                use_case=use_case,
                provider_key=model.provider_key,
                model_id=model.model_id,
                classifications=["none"],
                caller=caller,
            ),
        ),
        (
            "ai.policy.set_rank",
            lambda: settings.set_destination_rank(
                tenant_id,
                use_case=use_case,
                provider_key=model.provider_key,
                model_id=model.model_id,
                rank=0,
                caller=caller,
            ),
        ),
        (
            "ai.policy.set_preferences",
            lambda: settings.set_tenant_ai_preferences(
                tenant_id, exclude_training_use=True, caller=caller
            ),
        ),
        (
            "ai.budget.set_cap",
            lambda: settings.set_tenant_budget_cap(
                tenant_id, currency="USD", amount=Decimal("5"), caller=caller
            ),
        ),
    ]


def _enable(manager: UserCaller, tenant_id: uuid.UUID, catalogue: _Catalogue) -> object:
    return consumer_settings.enable_note_summaries(
        manager,
        tenant_id=tenant_id,
        provider_key=catalogue.model.provider_key,
        model_id=catalogue.model.model_id,
    )


# --- the consumer uses public imports only ------------------------------------------


@pytest.mark.parametrize("module", [consumer_settings, consumer])
def test_the_consumer_imports_only_the_public_inference_interface(module: ModuleType) -> None:
    source = Path(str(module.__file__)).read_text(encoding="utf-8")
    imported: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
        elif isinstance(node, ast.Import):
            imported += [a.name for a in node.names]
    saas_os_imports = [m for m in imported if m.split(".")[0] == "saas_os"]
    assert saas_os_imports
    assert all(m in {"saas_os.inference", "saas_os.inference.settings"} for m in saas_os_imports)


# --- end to end -------------------------------------------------------------------------


async def test_ai_is_off_for_a_new_tenant_and_the_call_is_refused(
    world: AIWorld, plans: list[str], fake_provider: FakeAdapter
) -> None:
    catalogue = _Catalogue(world)
    tenant_id = world.tenant()
    manager = world.member(tenant_id, *_MANAGER_PERMISSIONS)
    member = world.member(tenant_id, ("ai.inference", "run"))
    _entitle(plans, tenant_id)
    view = settings.read_tenant_ai_policy(tenant_id, caller=manager)
    assert (view.exists, view.enabled, view.use_cases, view.destinations) == (False, False, (), ())
    with pytest.raises(InferencePolicyDeniedError):
        await consumer.summarize_note(member, tenant_id=tenant_id, alias=catalogue.alias, note="x")
    assert fake_provider.calls == [] and attempts(tenant_id) == []


async def test_a_product_enables_ai_and_completes_a_call_with_public_imports_only(
    world: AIWorld, plans: list[str], fake_provider: FakeAdapter
) -> None:
    catalogue = _Catalogue(world)
    tenant_id = world.tenant()
    manager = world.member(tenant_id, *_MANAGER_PERMISSIONS)
    member = world.member(tenant_id, ("ai.inference", "run"))
    _entitle(plans, tenant_id)

    view = _enable(manager, tenant_id, catalogue)
    assert isinstance(view, settings.TenantAIPolicyView)
    assert view.enabled
    assert [(u.use_case, u.classifications) for u in view.use_cases] == [
        (consumer.SUMMARIZE_NOTE.name, ("none", "tenant_data"))
    ]
    (granted,) = view.destinations
    assert (granted.provider_key, granted.preference_rank, granted.enabled) == (
        catalogue.model.provider_key,
        0,
        True,
    )
    assert view.preferences.exclude_training_use
    for action in _POLICY_ACTIONS:
        assert _audit(tenant_id, action, "success") == 1, action

    models = consumer_settings.note_summary_models(manager, tenant_id=tenant_id)
    (chosen,) = [m for m in models if m.provider_key == catalogue.model.provider_key]
    assert (chosen.eligible, chosen.granted, chosen.blocked_by) == (True, True, ())

    result = await consumer.summarize_note(
        member, tenant_id=tenant_id, alias=catalogue.alias, note="the invoice is wrong"
    )
    assert result.output[0].text == "the invoice is wrong"  # the fake echoes the last turn
    assert result.provider_key == catalogue.model.provider_key
    (call,) = fake_provider.calls
    assert call.request.system == "Summarize in one line."
    (row,) = attempts(tenant_id)
    assert row["state"] == "succeeded" and row["use_case"] == consumer.SUMMARIZE_NOTE.name


async def test_a_platform_hold_refuses_the_call_whatever_the_tenant_allows(
    world: AIWorld, plans: list[str], fake_provider: FakeAdapter
) -> None:
    catalogue = _Catalogue(world)
    tenant_id = world.tenant()
    manager = world.member(tenant_id, *_MANAGER_PERMISSIONS)
    member = world.member(tenant_id, ("ai.inference", "run"))
    _entitle(plans, tenant_id)
    _enable(manager, tenant_id, catalogue)
    ai_hold.set_tenant_ai_hold(
        tenant_id, reason=HoldReason.SECURITY, caller=world.operator(P.AI_TENANT_HOLD_MANAGE)
    )
    with pytest.raises(InferencePolicyDeniedError) as denied:
        await consumer.summarize_note(member, tenant_id=tenant_id, alias=catalogue.alias, note="x")
    assert denied.value.reason == "tenant_ai_held"
    # The tenant can still write its settings; the hold still decides.
    assert settings.set_tenant_ai_policy(tenant_id, enabled=True, caller=manager) is True
    with pytest.raises(InferencePolicyDeniedError) as again:
        await consumer.summarize_note(member, tenant_id=tenant_id, alias=catalogue.alias, note="x")
    assert again.value.reason == "tenant_ai_held"
    assert fake_provider.calls == [] and attempts(tenant_id) == []


# --- authority -------------------------------------------------------------------------


def test_every_change_needs_its_permission_and_a_refusal_changes_nothing(
    world: AIWorld,
) -> None:
    catalogue = _Catalogue(world)
    tenant_id = world.tenant()
    member = world.member(tenant_id, ("ai.inference", "run"))
    for action, write in _every_write(member, tenant_id, catalogue.model):
        with pytest.raises(AuthorityNotAuthorizedError):
            write()
        assert _audit(tenant_id, action, "denied") >= 1, action
    reads: list[Callable[[], object]] = [
        lambda: settings.read_tenant_ai_policy(tenant_id, caller=member),
        lambda: settings.list_eligible_models(
            tenant_id, use_case=consumer.SUMMARIZE_NOTE.name, caller=member
        ),
        lambda: settings.read_tenant_budget(tenant_id, caller=member),
    ]
    for read in reads:
        with pytest.raises(AuthorityNotAuthorizedError):
            read()
    assert _setting_rows(tenant_id) == 0


def test_policy_read_alone_changes_nothing(world: AIWorld) -> None:
    catalogue = _Catalogue(world)
    tenant_id = world.tenant()
    reader = world.member(tenant_id, ("ai.policy", "read"))
    assert not settings.read_tenant_ai_policy(tenant_id, caller=reader).exists
    for _, write in _every_write(reader, tenant_id, catalogue.model):
        with pytest.raises(AuthorityNotAuthorizedError):
            write()
    assert _setting_rows(tenant_id) == 0


def test_support_access_never_changes_a_setting(world: AIWorld) -> None:
    catalogue = _Catalogue(world)
    tenant_id = world.tenant()
    engineer = _support_engineer(world, tenant_id)
    for action, write in _every_write(engineer, tenant_id, catalogue.model):
        with pytest.raises(AuthorityNotAuthorizedError):
            write()
        assert _audit(tenant_id, action, "denied") >= 1, action
    with pytest.raises(AuthorityNotAuthorizedError):
        settings.read_tenant_budget(tenant_id, caller=engineer)
    # Reading the policy and the eligibility view is `ai.policy:read`, which
    # support access may use (unchanged from the internal functions).
    assert not settings.read_tenant_ai_policy(tenant_id, caller=engineer).exists
    assert settings.list_eligible_models(
        tenant_id, use_case=consumer.SUMMARIZE_NOTE.name, caller=engineer
    )
    assert _setting_rows(tenant_id) == 0


def test_a_user_of_one_tenant_cannot_change_another(world: AIWorld) -> None:
    catalogue = _Catalogue(world)
    tenant_a = world.tenant()
    tenant_b = world.tenant()
    manager_a = world.member(tenant_a, *_MANAGER_PERMISSIONS)
    for _, write in _every_write(manager_a, tenant_b, catalogue.model):
        with pytest.raises(AuthorityNotAuthorizedError):
            write()
    with pytest.raises(AuthorityNotAuthorizedError):
        settings.read_tenant_ai_policy(tenant_b, caller=manager_a)
    with pytest.raises(AuthorityNotAuthorizedError):
        settings.read_tenant_budget(tenant_b, caller=manager_a)
    assert _setting_rows(tenant_b) == 0


def test_a_service_account_cannot_set_the_budget_cap(world: AIWorld) -> None:
    tenant_id = world.tenant()
    robot = ServiceAccountCaller(service_account_id=uuid.uuid4(), tenant_id=tenant_id)
    with pytest.raises(AuthorityNotAuthorizedError):
        settings.set_tenant_budget_cap(tenant_id, currency="USD", amount=Decimal("5"), caller=robot)
    assert _setting_rows(tenant_id) == 0


# --- grant-time validation ------------------------------------------------------------------


def test_a_model_installation_policy_does_not_allow_cannot_be_granted(world: AIWorld) -> None:
    catalogue = _Catalogue(world, allow=("none",))
    tenant_id = world.tenant()
    manager = world.member(tenant_id, *_MANAGER_PERMISSIONS)
    settings.set_tenant_ai_policy(tenant_id, enabled=True, caller=manager)
    settings.grant_use_case(
        tenant_id,
        use_case=consumer.SUMMARIZE_NOTE.name,
        classifications=["none", "tenant_data"],
        caller=manager,
    )
    with pytest.raises(settings.AITenantPolicyError) as refused:
        settings.grant_destination(
            tenant_id,
            use_case=consumer.SUMMARIZE_NOTE.name,
            provider_key=catalogue.model.provider_key,
            model_id=catalogue.model.model_id,
            classifications=["none", "tenant_data"],
            caller=manager,
        )
    assert refused.value.reason == "destination_not_eligible"
    assert "destination_policy_denied" in refused.value.blocked_by
    assert settings.read_tenant_ai_policy(tenant_id, caller=manager).destinations == ()


def test_a_model_failing_the_tenants_requirements_cannot_be_granted(world: AIWorld) -> None:
    catalogue = _Catalogue(world)
    trains = catalogue.add_model(world, training_use=True, allow=("none", "tenant_data"))
    tenant_id = world.tenant()
    manager = world.member(tenant_id, *_MANAGER_PERMISSIONS)
    settings.set_tenant_ai_policy(tenant_id, enabled=True, caller=manager)
    settings.grant_use_case(
        tenant_id,
        use_case=consumer.SUMMARIZE_NOTE.name,
        classifications=["none"],
        caller=manager,
    )
    settings.set_tenant_ai_preferences(tenant_id, exclude_training_use=True, caller=manager)
    with pytest.raises(settings.AITenantPolicyError) as refused:
        settings.grant_destination(
            tenant_id,
            use_case=consumer.SUMMARIZE_NOTE.name,
            provider_key=trains.provider_key,
            model_id=trains.model_id,
            classifications=["none"],
            caller=manager,
        )
    assert "training_use" in refused.value.blocked_by
    with pytest.raises(settings.AIConfigurationNotFoundError):
        settings.grant_destination(
            tenant_id,
            use_case=consumer.SUMMARIZE_NOTE.name,
            provider_key=unique("absent"),
            model_id="model-1",
            classifications=["none"],
            caller=manager,
        )


# --- the tenant's own budget cap ---------------------------------------------------------------


def test_the_tenant_sets_its_own_cap_and_reads_its_budget(world: AIWorld) -> None:
    tenant_id = world.tenant()
    manager = world.member(tenant_id, *_MANAGER_PERMISSIONS)
    before = settings.read_tenant_budget(tenant_id, caller=manager)
    assert before.state == settings.BudgetState.UNCONFIGURED
    consumer_settings.cap_monthly_ai_spend(
        manager, tenant_id=tenant_id, currency="USD", amount=Decimal("25")
    )
    assert _audit(tenant_id, "ai.budget.set_cap", "success") == 1
    assert isinstance(settings.read_tenant_budget(tenant_id, caller=manager), settings.BudgetStatus)
    with pytest.raises(settings.AIBudgetError):
        settings.set_tenant_budget_cap(
            tenant_id, currency="usd", amount=Decimal("1"), caller=manager
        )
