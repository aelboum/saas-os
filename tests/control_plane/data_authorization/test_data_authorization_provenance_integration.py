"""Integration tests for `control_plane.data_authorization.service
.verify_data_authorization_provenance()` (CP-02, Phase J, third pass:
Decision Provenance / Authenticity) against a real PostgreSQL instance.

A `DataAuthorizationDecision` is same-process, non-persisted, non-
cryptographically-bound -- any caller with ordinary in-process code
execution can construct a plausible one. This function is what makes a
decision's ALLOW outcome meaningful to a consumer: it requires a genuine,
matching `core.audit_log` record -- written by `authorize_data_access()`
itself, never by the consumer -- for the *current* tenant, this decision
type's own fixed `resource_type`/`action`, and a successful outcome.

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/control_plane/data_authorization/test_data_authorization_provenance_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.identity.service import create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from infra.secrets.config import get_secrets_provider
from sqlalchemy import text

from control_plane.data_authorization import (
    DataAuthorizationDecision,
    DataAuthorizationOutcome,
    DataAuthorizationRequest,
    ProviderEligibilityPolicy,
    TenantAIDataPolicy,
    authorize_data_access,
)
from control_plane.data_authorization.service import (
    _AUDIT_ACTION_APPROVED,
    _AUDIT_RESOURCE_TYPE,
    verify_data_authorization_provenance,
)
from control_plane.orchestration.service import _data_authorization_satisfied
from core.audit_log import ActorType, AuditOutcome
from core.audit_log import record as record_audit_event
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
    tenant_a = create_tenant(_unique("data-auth-prov-tenant-a"))
    tenant_b = create_tenant(_unique("data-auth-prov-tenant-b"))
    actor = create_user()
    yield tenant_a, tenant_b, actor
    _admin_delete_audit_log_for_tenant(tenant_a.id)
    _admin_delete_audit_log_for_tenant(tenant_b.id)
    with session_scope() as session:
        session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(actor.id)})
        session.execute(
            text("DELETE FROM core.tenants WHERE id IN (:a, :b)"),
            {"a": str(tenant_a.id), "b": str(tenant_b.id)},
        )


def _genuine_allow_decision(tenant_id: uuid.UUID, actor_id: uuid.UUID) -> DataAuthorizationDecision:
    policy = TenantAIDataPolicy(
        tenant_id=tenant_id,
        allowed_data_classifications=frozenset({"tenant_data"}),
        allowed_purposes=frozenset({"support_response_drafting"}),
        allowed_providers=frozenset({"anthropic"}),
    )
    provider_policy = ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic"}))
    request = DataAuthorizationRequest(
        tenant_id=tenant_id,
        data_classification="tenant_data",
        purpose="support_response_drafting",
        provider="anthropic",
        resource_type="support_ticket",
        resource_id="ticket-1",
    )
    return authorize_data_access(
        request, tenant_policy=policy, provider_policy=provider_policy, actor_user_id=actor_id
    )


class TestGenuineDecisionSatisfies:
    """Item 4/13 -- a genuinely evaluator-produced ALLOW decision, with
    real matching audit provenance, is accepted. This is the true-positive
    case moved out of `test_data_authorization_gate_unit.py` (which can no
    longer be a database-free unit test for this one case)."""

    def test_allow_for_matching_tenant_with_real_provenance_satisfies(self, fx) -> None:
        tenant_a, _tenant_b, actor = fx
        decision = _genuine_allow_decision(tenant_a.id, actor.id)
        assert verify_data_authorization_provenance(decision, tenant_id=tenant_a.id) is True
        assert _data_authorization_satisfied(decision, tenant_id=tenant_a.id) is True


class TestForgedDecisionIsRejected:
    """Item 1/12 -- a plausible forged decision (every visible field
    copied from a genuine one, only `decision_id` fresh) is rejected."""

    def test_forged_decision_with_fresh_decision_id_is_rejected(self, fx) -> None:
        tenant_a, _tenant_b, actor = fx
        genuine = _genuine_allow_decision(tenant_a.id, actor.id)
        forged = DataAuthorizationDecision(
            outcome=genuine.outcome,
            tenant_id=genuine.tenant_id,
            data_classification=genuine.data_classification,
            purpose=genuine.purpose,
            provider=genuine.provider,
            reason=None,
        )
        assert forged.decision_id != genuine.decision_id
        assert verify_data_authorization_provenance(forged, tenant_id=tenant_a.id) is False
        assert _data_authorization_satisfied(forged, tenant_id=tenant_a.id) is False


class TestWrongTenantProvenanceIsRejected:
    """Item 5 -- a decision_id genuinely audited for Tenant A must not
    satisfy a lookup for Tenant B, even when the (forged) decision object
    itself claims Tenant B -- the provenance query is tenant-scoped, so
    reusing a real Tenant-A decision_id under a different claimed tenant
    finds nothing."""

    def test_reusing_tenant_as_decision_id_for_tenant_b_is_rejected(self, fx) -> None:
        tenant_a, tenant_b, actor = fx
        genuine_a = _genuine_allow_decision(tenant_a.id, actor.id)

        claims_tenant_b = DataAuthorizationDecision(
            outcome=DataAuthorizationOutcome.ALLOW,
            tenant_id=tenant_b.id,
            data_classification=genuine_a.data_classification,
            purpose=genuine_a.purpose,
            provider=genuine_a.provider,
            reason=None,
        )
        # Reuse Tenant A's own genuinely-audited decision_id -- the one
        # concrete UUID a real audit row exists for -- under a claimed
        # Tenant B. If the check only matched on decision_id (ignoring
        # tenant scoping), this would incorrectly satisfy.
        object.__setattr__(claims_tenant_b, "decision_id", genuine_a.decision_id)

        assert verify_data_authorization_provenance(claims_tenant_b, tenant_id=tenant_b.id) is False


class TestWrongResourceTypeIsRejected:
    """Item 6 -- an audit row exists for this exact tenant/decision_id/
    action/success outcome, but under a *different* resource_type (e.g.
    it was actually the record of an unrelated audited event that
    happened to reuse this UUID as its resource_id) must not satisfy this
    decision type's own provenance check."""

    def test_audit_row_under_different_resource_type_does_not_satisfy(self, fx) -> None:
        tenant_a, _tenant_b, actor = fx
        forged = DataAuthorizationDecision(
            outcome=DataAuthorizationOutcome.ALLOW,
            tenant_id=tenant_a.id,
            data_classification="tenant_data",
            purpose="support_response_drafting",
            provider="anthropic",
            reason=None,
        )
        record_audit_event(
            tenant_id=tenant_a.id,
            actor_type=ActorType.USER,
            actor_user_id=actor.id,
            action=_AUDIT_ACTION_APPROVED,
            resource_type="some_unrelated_resource_type",
            resource_id=str(forged.decision_id),
            outcome=AuditOutcome.SUCCESS,
        )
        assert verify_data_authorization_provenance(forged, tenant_id=tenant_a.id) is False


class TestWrongActionIsRejected:
    """Item 8 -- an audit row exists for the right tenant/resource_type/
    resource_id/outcome=success, but under a *different* action name (not
    the one `authorize_data_access()` actually uses for an ALLOW) --
    proves the check compares the full tuple, not merely "any success row
    for this resource_id"."""

    def test_audit_row_with_wrong_action_does_not_satisfy(self, fx) -> None:
        tenant_a, _tenant_b, actor = fx
        forged = DataAuthorizationDecision(
            outcome=DataAuthorizationOutcome.ALLOW,
            tenant_id=tenant_a.id,
            data_classification="tenant_data",
            purpose="support_response_drafting",
            provider="anthropic",
            reason=None,
        )
        record_audit_event(
            tenant_id=tenant_a.id,
            actor_type=ActorType.USER,
            actor_user_id=actor.id,
            action="some.unrelated.action",
            resource_type=_AUDIT_RESOURCE_TYPE,
            resource_id=str(forged.decision_id),
            outcome=AuditOutcome.SUCCESS,
        )
        assert verify_data_authorization_provenance(forged, tenant_id=tenant_a.id) is False


class TestDenyOutcomeCannotSatisfyAllow:
    """Item 9 -- a genuinely-audited DENY (real `resource_id`, real
    `_AUDIT_ACTION_DENIED` action, `outcome=denied`) cannot be replayed to
    satisfy an ALLOW consumer, even if a caller reuses its `decision_id`
    inside a hand-built decision object claiming ALLOW."""

    def test_genuine_deny_audit_trail_cannot_satisfy_a_claimed_allow(self, fx) -> None:
        tenant_a, _tenant_b, actor = fx
        policy = TenantAIDataPolicy(
            tenant_id=tenant_a.id,
            allowed_data_classifications=frozenset({"tenant_data"}),
            allowed_purposes=frozenset({"support_response_drafting"}),
            allowed_providers=frozenset(),  # anthropic not permitted -> DENY
        )
        provider_policy = ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic"}))
        request = DataAuthorizationRequest(
            tenant_id=tenant_a.id,
            data_classification="tenant_data",
            purpose="support_response_drafting",
            provider="anthropic",
            resource_type="support_ticket",
            resource_id="ticket-1",
        )
        real_deny = authorize_data_access(
            request, tenant_policy=policy, provider_policy=provider_policy, actor_user_id=actor.id
        )
        assert real_deny.outcome is DataAuthorizationOutcome.DENY

        # A caller constructs a *different* object, claiming ALLOW, but
        # reusing the real DENY's own audited decision_id.
        claims_allow = DataAuthorizationDecision(
            outcome=DataAuthorizationOutcome.ALLOW,
            tenant_id=tenant_a.id,
            data_classification="tenant_data",
            purpose="support_response_drafting",
            provider="anthropic",
            reason=None,
        )
        object.__setattr__(claims_allow, "decision_id", real_deny.decision_id)

        assert verify_data_authorization_provenance(claims_allow, tenant_id=tenant_a.id) is False
