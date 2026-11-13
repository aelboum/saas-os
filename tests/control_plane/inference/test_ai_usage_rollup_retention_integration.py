"""Monthly AI usage rollup expiry against a real PostgreSQL (owner decisions
of 2026-11-13; `saas_os.control_plane.inference.usage_rollup_retention`,
migration `e8a3c6f1d9b4`).

Pinned: disabled (the default) deletes nothing; enabled, a run deletes
exactly the rollup rows of months before the cutoff (current UTC month less
the setting), in every tenant, each batch under the tenant's own scope with
one `ai.usage_monthly.expired` row in that tenant's audit trail (count,
cutoff, period; actor and correlation); a longer setting keeps more; a
Python clock ahead of the database never reaches into the 24 months the
database trigger protects (the run skips those rows instead of failing); the
registered job reads its own switch, independent of the attempt retention,
and a malformed setting fails it before anything is deleted. Rows are
seeded directly.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from ai_inference_world import AIWorld
from saas_os.control_plane.inference.usage_rollup_retention import (
    AIUsageRollupRetentionConfigurationError,
    AIUsageRollupRetentionSettings,
    expire_ai_usage_rollups,
    rollup_cutoff,
)
from saas_os.core.authority import SystemActor, SystemActorKind, SystemCorrelation
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

ON = AIUsageRollupRetentionSettings(enabled=True, retention_months=24)
ACTOR = SystemActor(kind=SystemActorKind.MAINTENANCE, name="ai_usage_rollup_retention_test")


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
            conn.execute(text("SELECT 1 FROM control_plane.ai_usage_monthly LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    except ProgrammingError as exc:
        pytest.skip(f"rollup table missing -- run `alembic upgrade head`: {exc}")
    finally:
        probe.dispose()


@pytest.fixture
def world() -> Iterator[AIWorld]:
    w = AIWorld()
    try:
        yield w
    finally:
        w.cleanup()


def _admin(sql: str, **params: object) -> list[Any]:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(sql), params)
            return list(result.all()) if result.returns_rows else []
    finally:
        engine.dispose()


def _now() -> datetime:
    return datetime.now(UTC)


def _months_back(months: int) -> datetime:
    return rollup_cutoff(_now(), months)


def _row(tenant_id: uuid.UUID, months_back: int) -> None:
    """One rollup row in the month `months_back` before the current one."""
    _admin(
        "INSERT INTO control_plane.ai_usage_monthly (id, tenant_id, month_start, "
        "provider_key, model_id, use_case, state, usage_provenance, currency, cost_unknown, "
        "attempts, input_tokens, output_tokens, cached_input_tokens, estimated_cost) "
        "VALUES (:i, :t, :m, :p, 'm1', 'uc', 'succeeded', 'provider_reported', 'USD', false, "
        "1, 10, 5, 0, 0.001)",
        i=uuid.uuid4(),
        t=tenant_id,
        m=_months_back(months_back),
        p=f"p{months_back}",
    )


def _months(tenant_id: uuid.UUID) -> set[int]:
    """The rows left, as months before the current one."""
    current = _months_back(0)
    rows = _admin(
        "SELECT month_start FROM control_plane.ai_usage_monthly WHERE tenant_id = :t",
        t=tenant_id,
    )
    out: set[int] = set()
    for (month_start,) in rows:
        at = month_start.astimezone(UTC)
        out.add((current.year - at.year) * 12 + current.month - at.month)
    return out


def _expired_rows(tenant_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = _admin(
        "SELECT actor_type, resource_id, metadata FROM core.audit_log "
        "WHERE tenant_id = :t AND action = 'ai.usage_monthly.expired' ORDER BY created_at",
        t=tenant_id,
    )
    out: list[dict[str, Any]] = []
    for actor_type, resource_id, metadata in rows:
        data = metadata if isinstance(metadata, dict) else json.loads(metadata)
        out.append({"actor_type": actor_type, "resource_id": resource_id, **data})
    return out


def _job_context(job_id: str) -> Any:
    from saas_os.control_plane.inference import attempt_retention_jobs as jobs
    from saas_os.infra.jobs.context import JobActor, SystemJobContext

    return SystemJobContext(
        system_actor=JobActor(kind="worker_job", name=jobs.AI_ATTEMPT_RETENTION_JOB_NAME),
        job_id=job_id,
    )


def _run_job(context: Any) -> None:
    import anyio

    from saas_os.control_plane.inference import attempt_retention_jobs as jobs

    handler: Any = jobs._purge_expired_ai_attempts_job  # pyright: ignore[reportPrivateUsage]
    anyio.run(handler, context)


def test_disabled_deletes_nothing(world: AIWorld) -> None:
    tenant_id = world.tenant()
    _row(tenant_id, 30)
    result = expire_ai_usage_rollups(
        actor=ACTOR, settings=AIUsageRollupRetentionSettings(False, 24)
    )
    assert (result.enabled, result.deleted, result.cutoff) == (False, 0, None)
    assert _months(tenant_id) == {30}


def test_only_months_before_the_cutoff_are_deleted_with_one_audit_row_per_batch(
    world: AIWorld,
) -> None:
    tenant_id = world.tenant()
    other_id = world.tenant()
    for months_back in (40, 30, 25, 24, 1, 0):
        _row(tenant_id, months_back)
    _row(other_id, 26)
    correlation = SystemCorrelation(arq_job_id="job-rollup-retention-1")

    result = expire_ai_usage_rollups(
        actor=ACTOR, correlation=correlation, settings=ON, batch_size=2
    )

    assert _months(tenant_id) == {24, 1, 0}
    assert _months(other_id) == set()
    assert result.cutoff == _months_back(24)
    assert result.deleted >= 4
    rows = _expired_rows(tenant_id)
    assert [r["deleted"] for r in rows] == [2, 1]
    for row in rows:
        assert row["actor_type"] == "system"
        assert row["resource_id"] is None
        assert row["cutoff"] == _months_back(24).isoformat()
        assert row["retention_months"] == 24
        assert row["system_actor"] == {"kind": "maintenance", "name": ACTOR.name}
        assert row["correlation"] == {"arq_job_id": "job-rollup-retention-1"}
    assert [r["deleted"] for r in _expired_rows(other_id)] == [1]

    # Idempotent: a second run finds nothing more.
    expire_ai_usage_rollups(actor=ACTOR, settings=ON)
    assert _months(tenant_id) == {24, 1, 0}
    assert len(_expired_rows(tenant_id)) == 2


def test_a_longer_setting_keeps_more(world: AIWorld) -> None:
    tenant_id = world.tenant()
    for months_back in (40, 30):
        _row(tenant_id, months_back)
    expire_ai_usage_rollups(actor=ACTOR, settings=AIUsageRollupRetentionSettings(True, 36))
    assert _months(tenant_id) == {30}


def test_a_clock_ahead_of_the_database_never_reaches_the_protected_months(
    world: AIWorld,
) -> None:
    tenant_id = world.tenant()
    for months_back in (25, 24):
        _row(tenant_id, months_back)
    # Two months ahead: Python's cutoff alone would take the database's month
    # 24 back; the database floor keeps it, and nothing raises.
    result = expire_ai_usage_rollups(actor=ACTOR, settings=ON, now=_now() + timedelta(days=62))
    assert _months(tenant_id) == {24}
    assert result.cutoff is not None and result.cutoff > _months_back(24)


def test_a_row_another_transaction_holds_is_skipped_and_taken_next_time(
    world: AIWorld,
) -> None:
    tenant_id = world.tenant()
    _row(tenant_id, 30)
    _row(tenant_id, 31)
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "SELECT id FROM control_plane.ai_usage_monthly "
                    "WHERE tenant_id = :t AND provider_key = 'p30' FOR UPDATE"
                ),
                {"t": tenant_id},
            )
            expire_ai_usage_rollups(actor=ACTOR, settings=ON)
    finally:
        engine.dispose()
    assert _months(tenant_id) == {30}
    expire_ai_usage_rollups(actor=ACTOR, settings=ON)
    assert _months(tenant_id) == set()


def test_the_registered_job_reads_its_own_switch(
    world: AIWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    from saas_os.control_plane.inference import attempt_retention_jobs as jobs

    tenant_id = world.tenant()
    _row(tenant_id, 30)
    context = _job_context("job-rollup-retention-2")

    monkeypatch.delenv("AI_USAGE_ROLLUP_RETENTION_ENABLED", raising=False)
    monkeypatch.delenv("AI_USAGE_ROLLUP_RETENTION_MONTHS", raising=False)
    monkeypatch.setenv("AI_ATTEMPT_RETENTION_ENABLED", "true")
    _run_job(context)
    assert _months(tenant_id) == {30}  # the attempt switch does not expire rollups

    monkeypatch.delenv("AI_ATTEMPT_RETENTION_ENABLED", raising=False)
    monkeypatch.setenv("AI_USAGE_ROLLUP_RETENTION_ENABLED", "true")
    _run_job(context)
    assert _months(tenant_id) == set()
    [row] = _expired_rows(tenant_id)
    assert row["system_actor"] == {
        "kind": "worker_job",
        "name": jobs.AI_ATTEMPT_RETENTION_JOB_NAME,
    }
    assert row["correlation"] == {"arq_job_id": "job-rollup-retention-2"}
    assert row["retention_months"] == 24


def test_a_malformed_setting_fails_the_job_before_anything_is_deleted(
    world: AIWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = world.tenant()
    _row(tenant_id, 30)
    very_old = (_now() - timedelta(days=200)).isoformat()
    _admin(
        "INSERT INTO control_plane.ai_inference_attempts (id, tenant_id, request_id, "
        "attempt_number, actor_type, use_case, alias, provider_key, model_id, "
        "provider_config_version, model_config_version, effective_classification, decision, "
        "state, started_at, finished_at, usage_provenance) VALUES (:i, :t, :r, 1, "
        "'service_account', 'uc', 'alias', 'p1', 'm1', 1, 1, 'tenant_data', "
        "CAST('{}' AS json), 'failed', CAST(:at AS timestamptz), CAST(:at AS timestamptz), "
        "'unknown')",
        i=uuid.uuid4(),
        t=tenant_id,
        r=uuid.uuid4(),
        at=very_old,
    )
    monkeypatch.setenv("AI_ATTEMPT_RETENTION_ENABLED", "true")
    monkeypatch.setenv("AI_USAGE_ROLLUP_RETENTION_ENABLED", "true")
    monkeypatch.setenv("AI_USAGE_ROLLUP_RETENTION_MONTHS", "12")
    with pytest.raises(AIUsageRollupRetentionConfigurationError):
        _run_job(_job_context("job-rollup-retention-3"))
    attempts = _admin(
        "SELECT count(*) FROM control_plane.ai_inference_attempts WHERE tenant_id = :t",
        t=tenant_id,
    )
    assert attempts[0][0] == 1
    assert 30 in _months(tenant_id)  # (the attempt adds its own, recent month)
