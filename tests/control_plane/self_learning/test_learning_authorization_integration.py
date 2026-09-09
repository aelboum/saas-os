"""Integration test proving `control_plane.self_learning.service
.authorize_learning_use()` writes exactly one real `core.audit_log`
entry per decision, allow or deny (docs/IMPLEMENTATION-ROADMAP.md Phase
9.2's own Audit Requirement: `learning.data_access_approved` /
`learning.data_access_denied`).

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/control_plane/self_learning/test_learning_authorization_integration.py
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

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning import (
    LearningAuthorizationOutcome,
    LearningAuthorizationRequest,
    LearningEvidence,
    TenantLearningPolicy,
    authorize_learning_use,
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
    tenant = create_tenant(_unique("learning-auth-tenant"))
    actor = create_user()
    yield tenant, actor
    _admin_delete_audit_log_for_tenant(tenant.id)
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(actor.id)})
        session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})


def _allowed_data_decision(tenant_id: uuid.UUID) -> DataAuthorizationDecision:
    return DataAuthorizationDecision(
        outcome=DataAuthorizationOutcome.ALLOW,
        tenant_id=tenant_id,
        data_classification="tenant_data",
        purpose="adaptive_prompt_tuning",
        provider="anthropic",
        reason=None,
    )


def test_allowed_decision_is_audited(fx) -> None:
    tenant, actor = fx
    policy = TenantLearningPolicy(
        tenant_id=tenant.id,
        allowed_purposes=frozenset({"adaptive_prompt_tuning"}),
        allowed_models_or_providers=frozenset({"anthropic"}),
        allowed_retentions=frozenset({"30d"}),
    )
    request = LearningAuthorizationRequest(
        tenant_id=tenant.id,
        purpose="adaptive_prompt_tuning",
        target_model_or_provider="anthropic",
        retention="30d",
        evidence=LearningEvidence(evidence_type="user_feedback", source_reference="feedback-1"),
    )

    decision = authorize_learning_use(
        request,
        data_authorization_decision=_allowed_data_decision(tenant.id),
        tenant_learning_policy=policy,
        actor_user_id=actor.id,
    )
    assert decision.outcome is LearningAuthorizationOutcome.ALLOW

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.data_access_approved"]
    assert len(matching) == 1
    assert matching[0].outcome == "success"
    assert matching[0].actor_user_id == actor.id
    assert matching[0].resource_id == str(decision.decision_id)
    assert matching[0].entry_metadata is not None
    # never the evidence's own content beyond its declared reference/type
    assert matching[0].entry_metadata["evidence_source_reference"] == "feedback-1"


def test_denied_decision_is_audited(fx) -> None:
    tenant, actor = fx
    request = LearningAuthorizationRequest(
        tenant_id=tenant.id,
        purpose="adaptive_prompt_tuning",
        target_model_or_provider="anthropic",
        retention="30d",
        evidence=LearningEvidence(evidence_type="user_feedback", source_reference="feedback-1"),
    )

    decision = authorize_learning_use(
        request,
        data_authorization_decision=_allowed_data_decision(tenant.id),
        tenant_learning_policy=None,  # no policy -> default deny
        actor_user_id=actor.id,
    )
    assert decision.outcome is LearningAuthorizationOutcome.DENY

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.data_access_denied"]
    assert len(matching) == 1
    assert matching[0].outcome == "denied"
    assert matching[0].entry_metadata is not None
    assert matching[0].entry_metadata["denial_reason"] == "no_learning_policy"


def test_cross_tenant_denied_decision_is_audited(fx) -> None:
    """Adversarial cross-tenant path: no `core.audit_log` entry claims
    ALLOW for an unauthorized cross-tenant learning attempt."""
    tenant, actor = fx
    other_tenant_id = uuid.uuid4()
    policy = TenantLearningPolicy(
        tenant_id=tenant.id,
        allowed_purposes=frozenset({"adaptive_prompt_tuning"}),
        allowed_models_or_providers=frozenset({"anthropic"}),
        allowed_retentions=frozenset({"30d"}),
    )
    request = LearningAuthorizationRequest(
        tenant_id=tenant.id,
        purpose="adaptive_prompt_tuning",
        target_model_or_provider="anthropic",
        retention="30d",
        evidence=LearningEvidence(evidence_type="user_feedback", source_reference="feedback-1"),
        cross_tenant_target_tenant_id=other_tenant_id,
    )

    decision = authorize_learning_use(
        request,
        data_authorization_decision=_allowed_data_decision(tenant.id),
        tenant_learning_policy=policy,
        cross_tenant_policy=None,
        actor_user_id=actor.id,
    )
    assert decision.outcome is LearningAuthorizationOutcome.DENY

    entries = list_audit_entries(tenant.id)
    matching = [e for e in entries if e.action == "learning.data_access_denied"]
    assert len(matching) == 1
    assert matching[0].entry_metadata is not None
    assert matching[0].entry_metadata["denial_reason"] == "cross_tenant_not_authorized"
    assert matching[0].entry_metadata["cross_tenant_target_tenant_id"] == str(other_tenant_id)
