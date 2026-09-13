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

from control_plane.data_authorization import (
    DataAuthorizationDecision,
    DataAuthorizationOutcome,
    DataAuthorizationRequest,
    ProviderEligibilityPolicy,
    TenantAIDataPolicy,
    authorize_data_access,
)
from control_plane.self_learning import (
    LearningAuthorizationOutcome,
    LearningAuthorizationRequest,
    LearningDenialReason,
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


def _allowed_data_decision(
    tenant_id: uuid.UUID, *, actor_user_id: uuid.UUID
) -> DataAuthorizationDecision:
    """CP-02 (Phase J, minimal correction): `authorize_learning_use()` now
    requires a genuine, matching `core.audit_log` provenance record for
    the upstream `DataAuthorizationDecision` it is given (see
    `control_plane.data_authorization.service
    .verify_data_authorization_provenance()`'s own docstring) before it
    will ever return ALLOW. A hand-built decision object (this helper's
    own previous implementation) is no longer sufficient for the ALLOW
    path -- it must be produced by the real `authorize_data_access()`
    entrypoint, so this fixture's ALLOW decisions are ones the platform's
    own audited evaluator actually wrote to `core.audit_log`."""
    return authorize_data_access(
        DataAuthorizationRequest(
            tenant_id=tenant_id,
            data_classification="tenant_data",
            purpose="adaptive_prompt_tuning",
            provider="anthropic",
            resource_type="learning_authorization_fixture",
            resource_id="fixture",
        ),
        tenant_policy=TenantAIDataPolicy(
            tenant_id=tenant_id,
            allowed_data_classifications=frozenset({"tenant_data"}),
            allowed_purposes=frozenset({"adaptive_prompt_tuning"}),
            allowed_providers=frozenset({"anthropic"}),
        ),
        provider_policy=ProviderEligibilityPolicy(eligible_providers=frozenset({"anthropic"})),
        actor_user_id=actor_user_id,
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
        data_authorization_decision=_allowed_data_decision(tenant.id, actor_user_id=actor.id),
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
        data_authorization_decision=_allowed_data_decision(tenant.id, actor_user_id=actor.id),
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
        data_authorization_decision=_allowed_data_decision(tenant.id, actor_user_id=actor.id),
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


class TestCP02DataAuthorizationLaunderingIsBlocked:
    """CP-02 (Phase J, minimal correction): a forged, never-audited
    `DataAuthorizationDecision` must not be laundered by
    `authorize_learning_use()` into a genuinely-audited
    `LearningAuthorizationDecision` ALLOW. Before this correction,
    `evaluate_learning_authorization()`'s own field checks (tenant match,
    outcome) were the only gate on the upstream decision -- `outcome`/
    `tenant_id` are trivially forgeable, and the resulting
    `LearningAuthorizationDecision` would still receive a *genuine* audit
    row from this real wrapper, passing every downstream
    `verify_learning_authorization_provenance()` check despite Data
    Authorization never having actually been passed."""

    def _valid_policy(self, tenant_id: uuid.UUID) -> TenantLearningPolicy:
        return TenantLearningPolicy(
            tenant_id=tenant_id,
            allowed_purposes=frozenset({"adaptive_prompt_tuning"}),
            allowed_models_or_providers=frozenset({"anthropic"}),
            allowed_retentions=frozenset({"30d"}),
        )

    def _request(self, tenant_id: uuid.UUID) -> LearningAuthorizationRequest:
        return LearningAuthorizationRequest(
            tenant_id=tenant_id,
            purpose="adaptive_prompt_tuning",
            target_model_or_provider="anthropic",
            retention="30d",
            evidence=LearningEvidence(evidence_type="user_feedback", source_reference="feedback-1"),
        )

    def test_forged_data_authorization_with_fresh_decision_id_is_rejected(self, fx) -> None:
        """Item A/B: a plausible forged `DataAuthorizationDecision` --
        valid-looking tenant_id, ALLOW outcome, valid-looking data
        classification, every visible field otherwise identical to a
        genuine one -- but a fresh, never-audited `decision_id` must
        produce a DENY, not an ALLOW."""
        tenant, actor = fx
        genuine_data_decision = _allowed_data_decision(tenant.id, actor_user_id=actor.id)
        forged = DataAuthorizationDecision(
            outcome=genuine_data_decision.outcome,
            tenant_id=genuine_data_decision.tenant_id,
            data_classification=genuine_data_decision.data_classification,
            purpose=genuine_data_decision.purpose,
            provider=genuine_data_decision.provider,
            reason=None,
        )
        assert forged.decision_id != genuine_data_decision.decision_id

        decision = authorize_learning_use(
            self._request(tenant.id),
            data_authorization_decision=forged,
            tenant_learning_policy=self._valid_policy(tenant.id),
            actor_user_id=actor.id,
        )

        assert decision.outcome is LearningAuthorizationOutcome.DENY
        assert decision.reason is LearningDenialReason.DATA_AUTHORIZATION_NOT_PASSED

    def test_forged_decision_with_correct_tenant_and_allow_outcome_is_still_rejected(
        self, fx
    ) -> None:
        """Item C: even with the correct tenant and an ALLOW outcome --
        the only two things the pre-correction field check verified --
        the decision is rejected because its `decision_id` has no
        authoritative audit provenance."""
        tenant, actor = fx
        forged = DataAuthorizationDecision(
            outcome=DataAuthorizationOutcome.ALLOW,
            tenant_id=tenant.id,
            data_classification="tenant_data",
            purpose="adaptive_prompt_tuning",
            provider="anthropic",
            reason=None,
        )

        decision = authorize_learning_use(
            self._request(tenant.id),
            data_authorization_decision=forged,
            tenant_learning_policy=self._valid_policy(tenant.id),
            actor_user_id=actor.id,
        )

        assert decision.outcome is LearningAuthorizationOutcome.DENY
        assert decision.reason is LearningDenialReason.DATA_AUTHORIZATION_NOT_PASSED

    def test_genuine_data_authorization_still_permits_genuine_allow(self, fx) -> None:
        """Item D: the legitimate path -- a real `authorize_data_access()`
        -produced decision -- must still reach ALLOW. Not merely a
        duplicate of `test_allowed_decision_is_audited`: this test lives
        in the same class as the laundering-rejection tests to make the
        contrast between genuine and forged explicit at the call site."""
        tenant, actor = fx
        genuine_data_decision = _allowed_data_decision(tenant.id, actor_user_id=actor.id)

        decision = authorize_learning_use(
            self._request(tenant.id),
            data_authorization_decision=genuine_data_decision,
            tenant_learning_policy=self._valid_policy(tenant.id),
            actor_user_id=actor.id,
        )

        assert decision.outcome is LearningAuthorizationOutcome.ALLOW

    def test_laundering_attempt_produces_no_authoritative_allow_audit_record(self, fx) -> None:
        """Item E: the laundering path must not be able to create an
        authoritative Learning Authorization audit record claiming ALLOW.
        After a forged-input attempt, `core.audit_log` must contain a
        `learning.data_access_denied` entry for this decision and no
        `learning.data_access_approved` entry at all for this tenant."""
        tenant, actor = fx
        forged = DataAuthorizationDecision(
            outcome=DataAuthorizationOutcome.ALLOW,
            tenant_id=tenant.id,
            data_classification="tenant_data",
            purpose="adaptive_prompt_tuning",
            provider="anthropic",
            reason=None,
        )

        decision = authorize_learning_use(
            self._request(tenant.id),
            data_authorization_decision=forged,
            tenant_learning_policy=self._valid_policy(tenant.id),
            actor_user_id=actor.id,
        )
        assert decision.outcome is LearningAuthorizationOutcome.DENY

        entries = list_audit_entries(tenant.id)
        approved = [e for e in entries if e.action == "learning.data_access_approved"]
        assert approved == []
        denied = [e for e in entries if e.action == "learning.data_access_denied"]
        assert len(denied) == 1
        assert denied[0].resource_id == str(decision.decision_id)
        assert denied[0].entry_metadata is not None
        assert denied[0].entry_metadata["denial_reason"] == "data_authorization_not_passed"
