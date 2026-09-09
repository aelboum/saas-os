"""Integration test proving `control_plane.data_authorization.service
.authorize_data_access()` writes exactly one real `core.audit_log` entry
per decision, allow or deny (docs/IMPLEMENTATION-ROADMAP.md Phase 9.2's
own Audit Requirement).

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/control_plane/data_authorization/test_data_authorization_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.audit_log.service import list as list_audit_entries
from core.identity.service import create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from infra.secrets.config import get_secrets_provider
from sqlalchemy import text

from control_plane.data_authorization import (
    DataAuthorizationOutcome,
    DataAuthorizationRequest,
    ProviderEligibilityPolicy,
    TenantAIDataPolicy,
    authorize_data_access,
)
from core.tenancy import create_tenant

pytestmark = [pytest.mark.integration]


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")

    probe_engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.tenants LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"PostgreSQL/core.tenants not reachable: {exc}. "
            "Run `docker compose up -d db` and `alembic upgrade head` first."
        )
    finally:
        probe_engine.dispose()


@pytest.fixture(autouse=True)
def _environment_secrets_provider(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    get_secrets_provider.cache_clear()
    yield
    get_secrets_provider.cache_clear()


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def fx():
    tenant = create_tenant(_unique("data-auth-tenant"))
    actor = create_user()
    yield tenant, actor
    _admin_delete_audit_log_for_tenant(tenant.id)
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(actor.id)})
        session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})


def test_allowed_decision_is_audited(fx) -> None:
    tenant, actor = fx
    policy = TenantAIDataPolicy(
        tenant_id=tenant.id,
        allowed_data_classifications=frozenset({"tenant_data"}),
        allowed_purposes=frozenset({"support_response_drafting"}),
        allowed_providers=frozenset({"anthropic"}),
    )
    provider_policy = ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic"}))
    request = DataAuthorizationRequest(
        tenant_id=tenant.id,
        data_classification="tenant_data",
        purpose="support_response_drafting",
        provider="anthropic",
        resource_type="support_ticket",
        resource_id="ticket-1",
    )

    decision = authorize_data_access(
        request, tenant_policy=policy, provider_policy=provider_policy, actor_user_id=actor.id
    )
    assert decision.outcome is DataAuthorizationOutcome.ALLOW

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "ai_control_plane.data_access_approved"]
    assert len(matching) == 1
    assert matching[0].outcome == "success"
    assert matching[0].actor_user_id == actor.id
    assert matching[0].resource_id == str(decision.decision_id)


def test_denied_decision_is_audited(fx) -> None:
    tenant, actor = fx
    provider_policy = ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic"}))
    request = DataAuthorizationRequest(
        tenant_id=tenant.id,
        data_classification="tenant_data",
        purpose="support_response_drafting",
        provider="anthropic",
        resource_type="support_ticket",
        resource_id="ticket-1",
    )

    decision = authorize_data_access(
        request, tenant_policy=None, provider_policy=provider_policy, actor_user_id=actor.id
    )
    assert decision.outcome is DataAuthorizationOutcome.DENY

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "ai_control_plane.data_access_denied"]
    assert len(matching) == 1
    assert matching[0].outcome == "denied"
    assert matching[0].entry_metadata is not None
    assert matching[0].entry_metadata["denial_reason"] == "no_tenant_policy"
