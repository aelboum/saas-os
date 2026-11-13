"""AI attempt retention against a real PostgreSQL (owner decision of
2026-11-13; `saas_os.control_plane.inference.attempt_retention`).

Pinned: disabled (the default) deletes nothing; enabled, a run deletes
exactly the finished attempts that finished before the cutoff and have no
budget reservation -- never a `started` one, a recent one or a reserved
one -- in every tenant, each batch under the tenant's own scope with one
`ai.attempts.purged` row in that tenant's audit trail (count, cutoff and
period; actor and correlation from the job; no attempt id); the monthly
rollup keeps the deleted attempts' totals; a row another transaction holds
is skipped and taken by the next run; the registered job reads the settings
and records its job actor. Rows are seeded directly: no provider, no
network.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

import saas_os.core.identity.models  # noqa: F401  (registers core.users for audit FKs)
from ai_inference_world import REASON, AIWorld
from saas_os.control_plane.inference.attempt_retention import (
    AIAttemptRetentionSettings,
    purge_expired_ai_attempts,
)
from saas_os.control_plane.inference.config import service as ai_config
from saas_os.core.authority import SystemActor, SystemActorKind, SystemCorrelation
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=UTC)
ON = AIAttemptRetentionSettings(enabled=True, retention_days=100)
CUTOFF = NOW - timedelta(days=100)
OLD = (CUTOFF - timedelta(days=1)).isoformat()
RECENT = (CUTOFF + timedelta(days=1)).isoformat()
ACTOR = SystemActor(kind=SystemActorKind.MAINTENANCE, name="ai_attempt_retention_test")


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


def _attempt(tenant_id: uuid.UUID, *, finished: str | None, provider: str = "p1") -> uuid.UUID:
    """A finished attempt (`finished` set) or a `started` one, started one
    hour before it finished (or one day before the cutoff)."""
    attempt_id = uuid.uuid4()
    at = finished or OLD
    _admin(
        "INSERT INTO control_plane.ai_inference_attempts (id, tenant_id, request_id, "
        "attempt_number, actor_type, use_case, alias, provider_key, model_id, "
        "provider_config_version, model_config_version, effective_classification, decision, "
        "state, started_at, finished_at, input_tokens, output_tokens, usage_provenance, "
        "estimated_cost, currency) VALUES (:i, :t, :r, 1, 'service_account', 'uc', 'alias', "
        ":p, 'm1', 1, 1, 'tenant_data', CAST('{}' AS json), :s, "
        "CAST(:at AS timestamptz) - interval '1 hour', CAST(:fin AS timestamptz), "
        "10, 5, 'provider_reported', 0.001, 'USD')",
        i=attempt_id,
        t=tenant_id,
        r=uuid.uuid4(),
        p=provider,
        s="succeeded" if finished else "started",
        at=at,
        fin=finished,
    )
    return attempt_id


def _present(tenant_id: uuid.UUID) -> set[uuid.UUID]:
    rows = _admin(
        "SELECT id FROM control_plane.ai_inference_attempts WHERE tenant_id = :t", t=tenant_id
    )
    return {row[0] for row in rows}


def _rollup_attempts(tenant_id: uuid.UUID) -> int:
    rows = _admin(
        "SELECT coalesce(sum(attempts), 0) FROM control_plane.ai_usage_monthly "
        "WHERE tenant_id = :t",
        t=tenant_id,
    )
    return int(rows[0][0])


def _purge_rows(tenant_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = _admin(
        "SELECT actor_type, resource_id, metadata FROM core.audit_log "
        "WHERE tenant_id = :t AND action = 'ai.attempts.purged' ORDER BY created_at",
        t=tenant_id,
    )
    out: list[dict[str, Any]] = []
    for actor_type, resource_id, metadata in rows:
        data = metadata if isinstance(metadata, dict) else json.loads(metadata)
        out.append({"actor_type": actor_type, "resource_id": resource_id, **data})
    return out


def test_disabled_deletes_nothing(world: AIWorld) -> None:
    tenant_id = world.tenant()
    old = _attempt(tenant_id, finished=OLD)
    result = purge_expired_ai_attempts(
        actor=ACTOR, settings=AIAttemptRetentionSettings(False, 100), now=NOW
    )
    assert (result.enabled, result.deleted, result.cutoff) == (False, 0, None)
    assert _present(tenant_id) == {old}
    assert _purge_rows(tenant_id) == []


def test_only_old_finished_unreserved_attempts_are_deleted_and_the_rollup_keeps_them(
    world: AIWorld,
) -> None:
    tenant_id, other_id = world.tenant(), world.tenant()
    old = [_attempt(tenant_id, finished=OLD) for _ in range(3)]
    started = _attempt(tenant_id, finished=None)
    recent = _attempt(tenant_id, finished=RECENT)
    at_cutoff = _attempt(tenant_id, finished=CUTOFF.isoformat())
    other_old = _attempt(other_id, finished=OLD, provider="p2")
    rollup_before = (_rollup_attempts(tenant_id), _rollup_attempts(other_id))
    assert rollup_before == (5, 1)

    correlation = SystemCorrelation(arq_job_id="job-retention-1")
    result = purge_expired_ai_attempts(
        actor=ACTOR, correlation=correlation, settings=ON, now=NOW, batch_size=2
    )

    assert result.enabled and result.cutoff == CUTOFF
    assert result.deleted >= 4  # other tenants of a shared database may add to it
    assert _present(tenant_id) == {started, recent, at_cutoff}
    assert _present(other_id) == set()
    assert not set(old) & _present(tenant_id) and other_old not in _present(other_id)
    assert (_rollup_attempts(tenant_id), _rollup_attempts(other_id)) == rollup_before

    rows = _purge_rows(tenant_id)
    assert [r["deleted"] for r in rows] == [2, 1]  # one row per batch, batch_size 2
    for row in rows:
        assert row["actor_type"] == "system" and row["resource_id"] is None
        assert row["cutoff"] == CUTOFF.isoformat() and row["retention_days"] == 100
        assert row["system_actor"] == {"kind": "maintenance", "name": ACTOR.name}
        assert row["correlation"] == {"arq_job_id": "job-retention-1"}
        assert not any(str(a) in json.dumps(row) for a in old)
    assert [r["deleted"] for r in _purge_rows(other_id)] == [1]

    again = purge_expired_ai_attempts(actor=ACTOR, settings=ON, now=NOW)
    assert _present(tenant_id) == {started, recent, at_cutoff}
    assert len(_purge_rows(tenant_id)) == 2  # nothing deleted, nothing recorded
    assert again.enabled


@pytest.fixture
def _secret(monkeypatch: pytest.MonkeyPatch, platform_config_database: None) -> None:
    class _Secrets:
        def get(self, name: str) -> str | None:
            return "placeholder" if name.startswith("AI_TEST_") else None

    monkeypatch.setattr(ai_config, "get_secrets_provider", lambda: _Secrets())
    monkeypatch.setenv("AI_PROVIDER_CREDENTIALS", "AI_TEST_PROVIDER_KEY,AI_TEST_ROTATED")


@pytest.mark.usefixtures("_secret")
def test_an_attempt_with_a_budget_reservation_is_kept(world: AIWorld) -> None:
    scene = world.scene(destinations=1)
    target = scene.destinations[0]
    ai_config.set_model_price(
        provider_key=target.provider_key,
        model_id=target.model_id,
        pricing_version="v1",
        currency="USD",
        input_per_million=Decimal("3"),
        output_per_million=Decimal("15"),
        effective_from=NOW - timedelta(days=400),
        caller=scene.operator,
        reason=REASON,
    )
    price_id = _admin(
        "SELECT id FROM control_plane.ai_model_prices WHERE model_ref = :m", m=target.model_ref
    )[0][0]
    tenant_id = scene.tenant_id
    reserved = _attempt(tenant_id, finished=OLD)
    unreserved = _attempt(tenant_id, finished=OLD)
    period_id = uuid.uuid4()
    _admin(
        "INSERT INTO control_plane.ai_budget_periods (id, tenant_id, period_start, currency) "
        "VALUES (:i, :t, CAST(:s AS timestamptz), 'USD')",
        i=period_id,
        t=tenant_id,
        s="2026-07-01T00:00:00+00:00",
    )
    _admin(
        "INSERT INTO control_plane.ai_budget_reservations (id, tenant_id, period_id, "
        "attempt_id, request_id, attempt_number, price_id, currency, amount, settled_amount, "
        "state, resolved_at) VALUES (:i, :t, :p, :a, :r, 1, :price, 'USD', 0.002, 0.001, "
        "'settled', now())",
        i=uuid.uuid4(),
        t=tenant_id,
        p=period_id,
        a=reserved,
        r=uuid.uuid4(),
        price=price_id,
    )
    purge_expired_ai_attempts(actor=ACTOR, settings=ON, now=NOW)
    assert reserved in _present(tenant_id)
    assert unreserved not in _present(tenant_id)


def test_a_row_another_transaction_holds_is_skipped_and_taken_next_time(
    world: AIWorld,
) -> None:
    tenant_id = world.tenant()
    held = _attempt(tenant_id, finished=OLD)
    free = _attempt(tenant_id, finished=OLD)
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            conn.execute(
                text("SELECT id FROM control_plane.ai_inference_attempts WHERE id = :i FOR UPDATE"),
                {"i": held},
            )
            purge_expired_ai_attempts(actor=ACTOR, settings=ON, now=NOW)
            remaining = conn.execute(
                text("SELECT id FROM control_plane.ai_inference_attempts WHERE tenant_id = :t"),
                {"t": tenant_id},
            ).all()
            assert {row[0] for row in remaining} == {held}
    finally:
        engine.dispose()
    assert free not in _present(tenant_id)
    purge_expired_ai_attempts(actor=ACTOR, settings=ON, now=NOW)
    assert _present(tenant_id) == set()


def test_the_registered_job_reads_the_settings_and_records_its_actor(
    world: AIWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    import anyio

    from saas_os.control_plane.inference import attempt_retention_jobs as jobs
    from saas_os.infra.jobs.context import JobActor, SystemJobContext

    tenant_id = world.tenant()
    very_old = (datetime.now(UTC) - timedelta(days=200)).isoformat()
    _attempt(tenant_id, finished=very_old)
    context = SystemJobContext(
        system_actor=JobActor(kind="worker_job", name=jobs.AI_ATTEMPT_RETENTION_JOB_NAME),
        job_id="job-retention-2",
    )
    handler: Any = jobs._purge_expired_ai_attempts_job  # pyright: ignore[reportPrivateUsage]

    monkeypatch.delenv("AI_ATTEMPT_RETENTION_ENABLED", raising=False)
    anyio.run(handler, context)
    assert len(_present(tenant_id)) == 1  # off by default

    monkeypatch.setenv("AI_ATTEMPT_RETENTION_ENABLED", "true")
    anyio.run(handler, context)
    assert _present(tenant_id) == set()
    [row] = _purge_rows(tenant_id)
    assert row["system_actor"] == {
        "kind": "worker_job",
        "name": jobs.AI_ATTEMPT_RETENTION_JOB_NAME,
    }
    assert row["correlation"] == {"arq_job_id": "job-retention-2"}
    assert row["retention_days"] == 100
