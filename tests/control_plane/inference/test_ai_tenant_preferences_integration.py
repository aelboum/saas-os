"""Tenant AI preferences against a real PostgreSQL (ADR-0054 Phase AI-E;
ADR-0055 section 7).

Pinned: written only with `ai.policy:manage` at the tenant, with a tenant
audit row, refused (and recorded) otherwise, never by support access; RLS
isolates them; they narrow eligibility against the provider's *declared*
data handling and can never widen it; the attempt's decision records the
preferences version.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from ai_inference_world import REASON, AIWorld, Scene, admin_scalar, attempts, runtime
from saas_os.control_plane.inference import service
from saas_os.control_plane.inference.config import service as ai_config
from saas_os.control_plane.inference.config import tenant_policy
from saas_os.control_plane.inference.config.errors import AITenantPolicyError
from saas_os.control_plane.inference.errors import InferencePolicyDeniedError
from saas_os.control_plane.inference.types import ContentPart, InferenceRequest, Message
from saas_os.core.authority import UserCaller
from saas_os.core.rbac.errors import AuthorityNotAuthorizedError
from saas_os.core.rbac.service import approve_support_access, create_support_access_request
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
            conn.execute(text("SELECT 1 FROM control_plane.ai_tenant_preferences LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"AI tables missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Secrets:
        def get(self, name: str) -> str | None:
            return "placeholder" if name.startswith("AI_TEST_") else None

    monkeypatch.setattr(ai_config, "get_secrets_provider", lambda: _Secrets())


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


def _declare(scene: Scene, index: int, **handling: object) -> None:
    ai_config.set_provider_data_handling(
        key=scene.destinations[index].provider_key,
        residency=handling.get("residency", ()),  # type: ignore[arg-type]
        retention_days=handling.get("retention_days"),  # type: ignore[arg-type]
        training_use=bool(handling.get("training_use", False)),
        caller=scene.operator,
        reason=REASON,
    )


def test_preferences_are_written_with_the_tenant_permission_and_audited(world: AIWorld) -> None:
    scene = world.scene()
    view = tenant_policy.set_tenant_ai_preferences(
        scene.tenant_id,
        allowed_residency=["eu", "ch"],
        max_retention_days=30,
        exclude_training_use=True,
        caller=scene.manager,
    )
    assert view.allowed_residency == ("ch", "eu") and view.version == 1
    read = tenant_policy.read_tenant_ai_policy(scene.tenant_id, caller=scene.manager)
    assert read.preferences == view
    assert (
        admin_scalar(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t "
            "AND action = 'ai.policy.set_preferences' AND outcome = 'success'",
            t=str(scene.tenant_id),
        )
        == 1
    )


def test_without_the_permission_or_through_support_access_it_is_refused(world: AIWorld) -> None:
    scene = world.scene()
    with pytest.raises(AuthorityNotAuthorizedError):
        tenant_policy.set_tenant_ai_preferences(
            scene.tenant_id, exclude_training_use=True, caller=scene.member
        )
    approver = world.member(scene.tenant_id, ("support_access_request", "approve"))
    engineer = world.user()
    request = create_support_access_request(
        caller=UserCaller(engineer),
        tenant_id=scene.tenant_id,
        reason="AI-E support boundary",
        requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    approve_support_access(caller=approver, tenant_id=scene.tenant_id, request_id=request.id)
    with pytest.raises(AuthorityNotAuthorizedError):
        tenant_policy.set_tenant_ai_preferences(
            scene.tenant_id, exclude_training_use=True, caller=UserCaller(engineer)
        )
    assert (
        admin_scalar(
            "SELECT count(*) FROM core.audit_log WHERE tenant_id = :t "
            "AND action = 'ai.policy.set_preferences' AND outcome = 'denied'",
            t=str(scene.tenant_id),
        )
        == 2
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"allowed_residency": ["EU"]},
        {"allowed_residency": ["a b"]},
        {"max_retention_days": -1},
        {"max_retention_days": 4000},
        {"max_retention_days": True},
    ],
)
def test_invalid_preferences_are_refused(world: AIWorld, kwargs: dict) -> None:
    scene = world.scene()
    with pytest.raises(AITenantPolicyError):
        tenant_policy.set_tenant_ai_preferences(scene.tenant_id, caller=scene.manager, **kwargs)


def test_preferences_are_isolated_by_tenant(world: AIWorld) -> None:
    a, b = world.scene(), world.scene()
    tenant_policy.set_tenant_ai_preferences(
        a.tenant_id, exclude_training_use=True, caller=a.manager
    )
    with tenant_session_scope(b.tenant_id) as session:
        assert (
            session.execute(
                text("SELECT count(*) FROM control_plane.ai_tenant_preferences")
            ).scalar_one()
            == 0
        )
    with pytest.raises(AuthorityNotAuthorizedError):
        tenant_policy.set_tenant_ai_preferences(
            b.tenant_id, exclude_training_use=True, caller=a.manager
        )


async def test_preferences_narrow_the_destinations_and_are_recorded(world: AIWorld) -> None:
    scene = world.scene(destinations=2)
    _declare(scene, 0, residency=["us"], retention_days=0, training_use=False)
    _declare(scene, 1, residency=["eu"], retention_days=0, training_use=False)
    prefs = tenant_policy.set_tenant_ai_preferences(
        scene.tenant_id, allowed_residency=["eu"], caller=scene.manager
    )
    rt, fake, _ = runtime()
    result = await service.run_inference(
        scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
    )
    # The first candidate is skipped by preference, not tried and failed.
    assert result.provider_key == scene.destinations[1].provider_key and result.attempts == 1
    (row,) = attempts(scene.tenant_id)
    assert row["decision"]["preferences_version"] == prefs.version
    assert len(fake.calls) == 1


async def test_an_undeclared_provider_fails_any_preference(world: AIWorld) -> None:
    scene = world.scene()
    tenant_policy.set_tenant_ai_preferences(
        scene.tenant_id, exclude_training_use=True, caller=scene.manager
    )
    rt, fake, _ = runtime()
    with pytest.raises(InferencePolicyDeniedError, match="no_eligible_destination"):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert fake.calls == [] and attempts(scene.tenant_id) == []


async def test_preferences_cannot_override_installation_policy(world: AIWorld) -> None:
    scene = world.scene()
    _declare(scene, 0, residency=["eu"], retention_days=0, training_use=False)
    ai_config.set_destination_policy(
        provider_key=scene.destinations[0].provider_key,
        classification="tenant_data",
        allowed=False,
        caller=scene.operator,
        reason="withdrawn",
    )
    tenant_policy.set_tenant_ai_preferences(
        scene.tenant_id, allowed_residency=["eu"], caller=scene.manager
    )
    rt, fake, _ = runtime()
    with pytest.raises(InferencePolicyDeniedError):
        await service.run_inference(
            scene.member, tenant_id=scene.tenant_id, request=_request(scene), runtime=rt
        )
    assert fake.calls == []
