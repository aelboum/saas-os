"""Migration test for `c7d2a9f4e1b6` (ADR-0054 amendment of 2026-11-11, Gap
22b: the monthly AI usage rollup).

At head: `control_plane.ai_usage_monthly` gives the application role SELECT,
INSERT and UPDATE (never DELETE) and carries the canonical tenant policy,
ENABLE and FORCE; its constraints refuse a non-month start, a negative sum
and a `started` state. The trigger on the attempts adds a finished attempt
once (an INSERT of a finished row, or the UPDATE that finishes a `started`
one), never a `started` one; an UPDATE of a finished attempt moves its counts;
a DELETE leaves the rollup alone. The application role's own write (the
governed path, under its tenant setting) is counted. The upgrade backfills
every finished attempt and nothing else; the downgrade drops the trigger,
both functions and the table, and the upgrade rebuilds it.

**Destructive to schema state for its duration**: downgrades one revision and
re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
Disposable databases only. Marked `integration`.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "c7d2a9f4e1b6"  # pragma: allowlist secret
_PREVIOUS = "f1b9d3e7a5c2"  # pragma: allowlist secret
_TABLE = "ai_usage_monthly"
_NONE3: tuple[int | None, int | None, int | None] = (None, None, None)


@pytest.fixture(scope="module")
def admin() -> Iterator[Engine]:
    get_migrations_database_config.cache_clear()
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"database not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM control_plane.ai_inference_attempts LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _seed_tenant(conn: Connection) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    conn.execute(
        text("INSERT INTO core.tenants (id, name, status) VALUES (:t, :n, 'active')"),
        {"t": tenant_id, "n": f"usage-rollup-{tenant_id.hex[:8]}"},
    )
    return tenant_id


def _attempt(
    conn: Connection,
    tenant_id: uuid.UUID,
    *,
    state: str = "succeeded",
    at: str = "2026-10-15T12:00:00+00:00",
    provider: str = "p1",
    provenance: str = "provider_reported",
    tokens: tuple[int | None, int | None, int | None] = (10, 5, 2),
    cost: str | None = "0.00100000",
    currency: str | None = "USD",
) -> uuid.UUID:
    attempt_id = uuid.uuid4()
    conn.execute(
        text(
            "INSERT INTO control_plane.ai_inference_attempts (id, tenant_id, request_id, "
            "attempt_number, actor_type, use_case, alias, provider_key, model_id, "
            "provider_config_version, model_config_version, effective_classification, "
            "decision, state, started_at, finished_at, input_tokens, output_tokens, "
            "cached_input_tokens, "
            "usage_provenance, estimated_cost, currency) VALUES (:i, :t, :r, 1, "
            "'service_account', 'uc', 'alias', :p, 'm1', 1, 1, 'tenant_data', "
            "CAST('{}' AS json), CAST(:s AS varchar), CAST(:at AS timestamptz), "
            "CASE WHEN CAST(:s AS varchar) = 'started' THEN NULL "
            "ELSE CAST(:at AS timestamptz) + interval '1 second' END, :in, :out, :cached, :prov, "
            "CAST(:cost AS numeric), :cur)"
        ),
        {
            "i": attempt_id,
            "t": tenant_id,
            "r": uuid.uuid4(),
            "p": provider,
            "s": state,
            "at": at,
            "in": tokens[0],
            "out": tokens[1],
            "cached": tokens[2],
            "prov": provenance,
            "cost": cost,
            "cur": currency,
        },
    )
    return attempt_id


def _unknown(conn: Connection, tenant_id: uuid.UUID, state: str, **kwargs: Any) -> uuid.UUID:
    """An attempt with no usage and no price."""
    return _attempt(
        conn,
        tenant_id,
        state=state,
        provenance="unknown",
        tokens=_NONE3,
        cost=None,
        currency=None,
        **kwargs,
    )


def _rollup(conn: Connection, tenant_id: uuid.UUID) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            text(
                "SELECT to_char(month_start AT TIME ZONE 'UTC', 'YYYY-MM') AS month, "
                "provider_key, state, usage_provenance, currency, cost_unknown, attempts, "
                "input_tokens, output_tokens, cached_input_tokens, estimated_cost "
                "FROM control_plane.ai_usage_monthly WHERE tenant_id = :t "
                "ORDER BY 1, 2, 3, 4, 5, 6"
            ),
            {"t": tenant_id},
        ).mappings()
    ]


def _granted(admin: Engine, role: str) -> set[str]:
    with admin.connect() as conn:
        return {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_schema = 'control_plane' AND table_name = :t AND grantee = :r"
                ),
                {"t": _TABLE, "r": role},
            )
        }


def _cleanup(admin: Engine, tenant_id: uuid.UUID) -> None:
    with admin.begin() as conn:
        for statement in (
            "DELETE FROM control_plane.ai_inference_attempts WHERE tenant_id = :t",
            "DELETE FROM control_plane.ai_usage_monthly WHERE tenant_id = :t",
            "DELETE FROM core.tenants WHERE id = :t",
        ):
            conn.execute(text(statement), {"t": tenant_id})


def test_the_grants_and_the_policy_are_exactly_the_reviewed_ones(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    app_role = os.environ.get("APP_DB_USER", "saas_os_app")
    config_role = os.environ.get("PLATFORM_CONFIG_DB_USER", "saas_os_platform_config")
    assert _granted(admin, app_role) == {"SELECT", "INSERT", "UPDATE"}
    assert _granted(admin, config_role) == set()
    with admin.connect() as conn:
        state = conn.execute(
            text(
                "SELECT c.relrowsecurity, c.relforcerowsecurity, (SELECT count(*) FROM "
                "pg_policies p WHERE p.schemaname = 'control_plane' AND p.tablename = :t) "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'control_plane' AND c.relname = :t"
            ),
            {"t": _TABLE},
        ).one()
    assert tuple(state) == (True, True, 1)


def _insert_rollup(conn: Connection, tenant_id: uuid.UUID, **overrides: object) -> None:
    values: dict[str, object] = {
        "month": "2026-10-01T00:00:00+00:00",
        "state": "succeeded",
        "attempts": 1,
        "cost": "0",
        "currency": "USD",
    }
    values.update(overrides)
    conn.execute(
        text(
            "INSERT INTO control_plane.ai_usage_monthly (id, tenant_id, month_start, "
            "provider_key, model_id, use_case, state, usage_provenance, currency, cost_unknown, "
            "attempts, input_tokens, output_tokens, cached_input_tokens, estimated_cost) "
            "VALUES (:i, :t, CAST(:month AS timestamptz), 'p', 'm', 'uc', :state, 'estimated', "
            ":currency, false, :attempts, 0, 0, 0, CAST(:cost AS numeric))"
        ),
        {"i": uuid.uuid4(), "t": tenant_id, **values},
    )


def test_the_table_enforces_its_constraints(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        trans = conn.begin()
        try:
            tenant_id = _seed_tenant(conn)
            _insert_rollup(conn, tenant_id)
            for bad in (
                {},  # one row per grain
                {"month": "2026-10-02T00:00:00+00:00"},  # not the first instant of a month
                {"state": "started"},  # a started attempt is never rolled up
                {"attempts": -1, "state": "failed"},
                {"cost": "-0.1", "state": "failed"},
                {"currency": "usd", "state": "failed"},
            ):
                with pytest.raises(IntegrityError), conn.begin_nested():
                    _insert_rollup(conn, tenant_id, **bad)
            _insert_rollup(conn, tenant_id, currency=None)
            with pytest.raises(IntegrityError), conn.begin_nested():
                _insert_rollup(conn, tenant_id, currency=None)  # NULLS NOT DISTINCT
        finally:
            trans.rollback()


def test_the_trigger_counts_each_finished_attempt_once(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        trans = conn.begin()
        try:
            tenant_id = _seed_tenant(conn)
            started = _attempt(conn, tenant_id, state="started", tokens=_NONE3, cost=None)
            assert _rollup(conn, tenant_id) == []  # a started attempt is not counted
            conn.execute(
                text(
                    "UPDATE control_plane.ai_inference_attempts SET state = 'succeeded', "
                    "finished_at = now(), "
                    "input_tokens = 7, output_tokens = 3, estimated_cost = 0.002 WHERE id = :i"
                ),
                {"i": started},
            )
            _attempt(conn, tenant_id)  # inserted finished: counted at once
            _unknown(conn, tenant_id, "failed")
            by_state = {r["state"]: r for r in _rollup(conn, tenant_id)}
            succeeded, failed = by_state["succeeded"], by_state["failed"]
            assert succeeded["attempts"] == 2
            assert (succeeded["input_tokens"], succeeded["output_tokens"]) == (17, 8)
            assert succeeded["cached_input_tokens"] == 2
            assert succeeded["estimated_cost"] == Decimal("0.003")
            assert (failed["attempts"], failed["cost_unknown"], failed["currency"]) == (
                1,
                True,
                None,
            )
            assert failed["input_tokens"] == 0  # unknown contributes nothing

            # An unrelated change to a finished attempt changes nothing.
            conn.execute(
                text(
                    "UPDATE control_plane.ai_inference_attempts SET duration_ms = 5 WHERE id = :i"
                ),
                {"i": started},
            )
            assert {r["state"]: r for r in _rollup(conn, tenant_id)}["succeeded"] == succeeded
            # A change of a counted figure moves it: old taken away, new added.
            conn.execute(
                text(
                    "UPDATE control_plane.ai_inference_attempts SET input_tokens = 20, "
                    "provider_key = 'p2' WHERE id = :i"
                ),
                {"i": started},
            )
            by_provider = {
                r["provider_key"]: r for r in _rollup(conn, tenant_id) if r["state"] == "succeeded"
            }
            assert (by_provider["p1"]["attempts"], by_provider["p1"]["input_tokens"]) == (1, 10)
            assert (by_provider["p2"]["attempts"], by_provider["p2"]["input_tokens"]) == (1, 20)
            # A deleted attempt stays counted: the rollup outlives the attempts.
            before = _rollup(conn, tenant_id)
            conn.execute(
                text("DELETE FROM control_plane.ai_inference_attempts WHERE tenant_id = :t"),
                {"t": tenant_id},
            )
            assert _rollup(conn, tenant_id) == before
        finally:
            trans.rollback()


def test_the_application_roles_own_write_is_counted_under_its_tenant(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    with admin.begin() as conn:
        tenant_id = _seed_tenant(conn)
        other_id = _seed_tenant(conn)
    with admin.begin() as conn:
        _attempt(conn, other_id)
    app = build_engine(get_database_config())
    try:
        with app.begin() as conn:
            conn.execute(
                text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)}
            )
            _attempt(conn, tenant_id, state="started", tokens=_NONE3, cost=None)
            conn.execute(
                text(
                    "UPDATE control_plane.ai_inference_attempts SET state = 'succeeded', "
                    "finished_at = now(), "
                    "input_tokens = 4, output_tokens = 1 WHERE tenant_id = :t"
                ),
                {"t": tenant_id},
            )
            # Tenant-scoped like everything else: the other tenant's row is
            # invisible from here.
            assert _rollup(conn, other_id) == []
        with admin.connect() as conn:
            (row,) = _rollup(conn, tenant_id)
            assert (row["attempts"], row["input_tokens"], row["output_tokens"]) == (1, 4, 1)
            assert len(_rollup(conn, other_id)) == 1
    finally:
        app.dispose()
        _cleanup(admin, tenant_id)
        _cleanup(admin, other_id)


def test_the_upgrade_backfills_finished_attempts_and_the_downgrade_drops_everything(
    admin: Engine,
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    with admin.begin() as conn:
        tenant_id = _seed_tenant(conn)
    try:
        command.downgrade(cfg, _PREVIOUS)
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT to_regclass('control_plane.ai_usage_monthly')")
                ).scalar_one()
                is None
            )
            functions = conn.execute(
                text(
                    "SELECT count(*) FROM pg_proc p JOIN pg_namespace s ON s.oid = "
                    "p.pronamespace WHERE s.nspname = 'control_plane' "
                    "AND p.proname LIKE 'ai_usage_monthly%'"
                )
            ).scalar_one()
            assert functions == 0
        with admin.begin() as conn:
            _attempt(conn, tenant_id, at="2026-09-30T23:59:59+00:00")
            _attempt(conn, tenant_id, at="2026-10-01T00:00:00+00:00")
            _attempt(conn, tenant_id, at="2026-10-31T10:00:00+00:00", provider="p2")
            _attempt(conn, tenant_id, state="started", tokens=_NONE3, cost=None)
            _unknown(conn, tenant_id, "abandoned")
        command.upgrade(cfg, _REVISION)
        with admin.connect() as conn:
            rows = _rollup(conn, tenant_id)
        summary = [
            (r["month"], r["provider_key"], r["state"], r["attempts"], r["input_tokens"])
            for r in rows
        ]
        assert summary == [
            ("2026-09", "p1", "succeeded", 1, 10),
            ("2026-10", "p1", "abandoned", 1, 0),
            ("2026-10", "p1", "succeeded", 1, 10),
            ("2026-10", "p2", "succeeded", 1, 10),
        ]
    finally:
        command.upgrade(cfg, "head")
        _cleanup(admin, tenant_id)
