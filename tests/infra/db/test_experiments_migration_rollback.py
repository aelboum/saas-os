"""Migration reversibility test for the Phase 9.6 self_learning.experiments
migration (docs/IMPLEMENTATION-ROADMAP.md Phase 9.6; this task's own
Rollback requirement: "if a migration exists: downgrade, verify schema
removed, upgrade, verify schema restored" -- run against real disposable
PostgreSQL, not just inspected).

**Destructive**: this test downgrades past, then re-applies,
`c0804e84948b` (the experiments-table migration) on whatever database
`MIGRATIONS_DATABASE_URL` points at -- it temporarily drops
`self_learning.experiments`, then recreates it empty. Run this only
against a disposable database, never a shared development or production
database. Marked `integration` and excluded from the default `pytest`
run for exactly this reason, mirroring
`tests/infra/db/test_audit_log_migration_rollback.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_experiments_migration_rollback.py
"""

from __future__ import annotations

import uuid
from pathlib import Path

# Registers core.users/core.tenants on the shared declarative Base.metadata
# (see tests/core/audit_log/test_audit_log_isolation_integration.py for the
# fuller explanation) -- required for the experiments table's ForeignKeys
# to resolve at model-import time, even though this file never otherwise
# needs core.identity directly.
import core.identity.models  # noqa: F401
import pytest
from alembic import command
from alembic.config import Config
from core.identity.service import create_user
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from control_plane.data_authorization import DataAuthorizationDecision, DataAuthorizationOutcome
from control_plane.self_learning.adaptive.models import AdaptationSurface
from control_plane.self_learning.adaptive.service import propose_adaptation
from control_plane.self_learning.experiments.service import create_experiment
from control_plane.self_learning.models import (
    LearningAuthorizationDecision,
    LearningAuthorizationOutcome,
)
from core.tenancy import create_tenant

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_EXPERIMENTS_REVISION = "c0804e84948b"
_ADAPTATIONS_REVISION = "582f6b7865e7"


@pytest.fixture(autouse=True)
def _require_reachable_privileged_database() -> None:
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured MIGRATIONS_DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first -- "
            "see this file's module docstring."
        )
    finally:
        probe_engine.dispose()


def _alembic_config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _table_exists(table: str) -> bool:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'self_learning' AND table_name = :t)"
                ),
                {"t": table},
            ).scalar_one()
        return bool(row)
    finally:
        engine.dispose()


def _rls_flags(table: str) -> tuple[bool, bool] | None:
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            row = session.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE relname = :t AND relnamespace = 'self_learning'::regnamespace"
                ),
                {"t": table},
            ).one_or_none()
        return (row[0], row[1]) if row is not None else None
    finally:
        engine.dispose()


def _allow_decision(tenant_id: uuid.UUID) -> LearningAuthorizationDecision:
    data_decision = DataAuthorizationDecision(
        outcome=DataAuthorizationOutcome.ALLOW,
        tenant_id=tenant_id,
        data_classification="tenant_data",
        purpose="experiment_analysis",
        provider="anthropic",
        reason=None,
    )
    return LearningAuthorizationDecision(
        outcome=LearningAuthorizationOutcome.ALLOW,
        tenant_id=tenant_id,
        purpose="experiment_analysis",
        reason=None,
        data_authorization_decision_id=data_decision.decision_id,
    )


def test_experiments_migration_upgrade_downgrade_upgrade_cycle_is_reversible() -> None:
    cfg = _alembic_config()

    # Ensure we start from a known state: fully upgraded.
    command.upgrade(cfg, "head")
    assert _table_exists("experiments")
    assert _rls_flags("experiments") == (True, True)
    # self_learning.adaptations (582f6b7865e7) must be present and untouched.
    assert _table_exists("adaptations")

    # --- seed a real experiment through the actual service layer (not
    # raw SQL) before downgrading, proving the schema this migration
    # created is genuinely usable, not merely structurally present ---
    tenant = create_tenant(f"experiments-rollback-{uuid.uuid4().hex[:8]}")
    agent = create_user()
    try:
        adaptation = propose_adaptation(
            tenant_id=tenant.id,
            surface=AdaptationSurface.PROMPT_INSTRUCTION,
            lineage_key="support_agent.system_prompt",
            proposed_value="Be courteous.",
            learning_purpose="adaptive_prompt_tuning",
            learning_authorization_decision=_allow_decision(tenant.id),
            evidence_type="user_feedback",
            evidence_source_reference="feedback-1",
            created_by_user_id=agent.id,
        )
        create_experiment(
            tenant_id=tenant.id,
            baseline_version="v0",
            learning_authorization_decision=_allow_decision(tenant.id),
            evidence_type="tool_output",
            evidence_source_reference="rollback-seed",
            created_by_user_id=agent.id,
            adaptation=adaptation,
        )

        try:
            # --- downgrade past the experiments migration ---
            command.downgrade(cfg, _ADAPTATIONS_REVISION)
            assert not _table_exists("experiments")
            # self_learning.adaptations and every earlier structure must
            # be untouched -- this downgrade does not drop the shared
            # self_learning schema (unlike 582f6b7865e7's own downgrade,
            # which is the last remaining table owner at that point).
            assert _table_exists("adaptations")
            assert _rls_flags("adaptations") == (True, True)

            # --- re-apply the experiments migration ---
            command.upgrade(cfg, _EXPERIMENTS_REVISION)
            assert _table_exists("experiments")
            assert _rls_flags("experiments") == (True, True)

            # experiments is usable again post-re-upgrade: a fresh row
            # succeeds (the old row was dropped with the table, which is
            # expected -- this proves the *schema* is usable again, not
            # that data survived a destructive downgrade).
            second_adaptation = propose_adaptation(
                tenant_id=tenant.id,
                surface=AdaptationSurface.RESPONSE_STRATEGY,
                lineage_key="support_agent.response_strategy",
                proposed_value="prefer-bullet-points",
                learning_purpose="adaptive_prompt_tuning",
                learning_authorization_decision=_allow_decision(tenant.id),
                evidence_type="user_feedback",
                evidence_source_reference="feedback-2",
                created_by_user_id=agent.id,
            )
            reseeded = create_experiment(
                tenant_id=tenant.id,
                baseline_version="v0",
                learning_authorization_decision=_allow_decision(tenant.id),
                evidence_type="tool_output",
                evidence_source_reference="rollback-reseed",
                created_by_user_id=agent.id,
                adaptation=second_adaptation,
            )
            assert reseeded.status == "configured"
        finally:
            command.upgrade(cfg, "head")
    finally:
        admin_engine = build_engine(get_migrations_database_config())
        try:
            admin_factory = build_session_factory(admin_engine)
            with session_scope(session_factory=admin_factory) as session:
                session.execute(
                    text("DELETE FROM self_learning.experiments WHERE tenant_id = :t"),
                    {"t": str(tenant.id)},
                )
                session.execute(
                    text("DELETE FROM self_learning.adaptations WHERE tenant_id = :t"),
                    {"t": str(tenant.id)},
                )
                session.execute(
                    text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant.id)}
                )
        finally:
            admin_engine.dispose()
        with session_scope() as session:
            session.execute(text("DELETE FROM core.users WHERE id = :id"), {"id": str(agent.id)})
            session.execute(text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(tenant.id)})
