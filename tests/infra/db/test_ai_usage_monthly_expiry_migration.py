"""Migration test for `e8a3c6f1d9b4` (owner decisions of 2026-11-13: the
monthly AI usage rollup expiry, behind a floor trigger, without `SECURITY
DEFINER`).

At head: the application role holds DELETE on
`control_plane.ai_usage_monthly`, is not a member of its owner, and the
`BEFORE DELETE` trigger refuses it, nothing deleted, any row of the current
UTC month or of the 24 whole months before it (by the database clock), while
an older row goes. The owner is let through. The trigger function is not
`SECURITY DEFINER` and pins its search path. The downgrade revokes DELETE
and drops the trigger and its function; the upgrade restores them.

**Destructive to schema state for its duration**: downgrades one revision and
re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
Disposable databases only. Marked `integration`.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "e8a3c6f1d9b4"  # pragma: allowlist secret
_PREVIOUS = "c7d2a9f4e1b6"  # pragma: allowlist secret
_TABLE = "control_plane.ai_usage_monthly"
_FUNCTION = "ai_usage_monthly_refuse_recent_delete"


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
            conn.execute(text("SELECT 1 FROM control_plane.ai_usage_monthly LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _app_role() -> str:
    return make_url(get_database_config().url).username or "saas_os_app"


def _can_delete(admin: Engine) -> bool:
    with admin.connect() as conn:
        return bool(
            conn.execute(
                text("SELECT has_table_privilege(:r, CAST(:t AS regclass), 'DELETE')"),
                {"r": _app_role(), "t": _TABLE},
            ).scalar_one()
        )


def _function(admin: Engine) -> tuple[bool, list[str] | None] | None:
    with admin.connect() as conn:
        row = conn.execute(
            text(
                "SELECT p.prosecdef, p.proconfig FROM pg_proc p JOIN pg_namespace n "
                "ON n.oid = p.pronamespace WHERE n.nspname = 'control_plane' AND p.proname = :f"
            ),
            {"f": _FUNCTION},
        ).one_or_none()
    return None if row is None else (bool(row[0]), row[1])


def _row(conn: Connection, tenant_id: uuid.UUID, months_back: int) -> uuid.UUID:
    """A rollup row `months_back` months before the database's current UTC
    month."""
    row_id = uuid.uuid4()
    conn.execute(
        text(
            "INSERT INTO control_plane.ai_usage_monthly (id, tenant_id, month_start, "
            "provider_key, model_id, use_case, state, usage_provenance, currency, cost_unknown, "
            "attempts, input_tokens, output_tokens, cached_input_tokens, estimated_cost) "
            "VALUES (:i, :t, (date_trunc('month', now() AT TIME ZONE 'UTC') "
            "- make_interval(months => :b)) AT TIME ZONE 'UTC', :p, 'm', 'uc', 'succeeded', "
            "'estimated', 'USD', false, 1, 0, 0, 0, 0)"
        ),
        {"i": row_id, "t": tenant_id, "b": months_back, "p": f"p{months_back}"},
    )
    return row_id


def _present(admin: Engine, tenant_id: uuid.UUID) -> set[uuid.UUID]:
    with admin.connect() as conn:
        return set(
            conn.execute(
                text("SELECT id FROM control_plane.ai_usage_monthly WHERE tenant_id = :t"),
                {"t": tenant_id},
            ).scalars()
        )


def test_at_head_the_application_role_may_delete_only_below_the_floor(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    assert _can_delete(admin)
    assert _function(admin) == (False, ["search_path=pg_catalog"])
    with admin.connect() as conn:
        member = conn.execute(
            text(
                "SELECT pg_has_role(:r, (SELECT relowner FROM pg_class "
                "WHERE oid = CAST(:t AS regclass)), 'MEMBER')"
            ),
            {"r": _app_role(), "t": _TABLE},
        ).scalar_one()
    assert member is False

    tenant_id = uuid.uuid4()
    with admin.begin() as conn:
        conn.execute(
            text("INSERT INTO core.tenants (id, name, status) VALUES (:t, :n, 'active')"),
            {"t": tenant_id, "n": f"rollup-expiry-{tenant_id.hex[:8]}"},
        )
        rows = {b: _row(conn, tenant_id, b) for b in (0, 1, 24, 25)}
    app = build_engine(get_database_config())
    try:
        for months_back in (0, 1, 24):
            with pytest.raises(DBAPIError, match="never deleted"), app.begin() as conn:
                conn.execute(
                    text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)}
                )
                conn.execute(
                    text("DELETE FROM control_plane.ai_usage_monthly WHERE id = :i"),
                    {"i": rows[months_back]},
                )
        with app.begin() as conn:
            conn.execute(
                text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)}
            )
            deleted = conn.execute(
                text("DELETE FROM control_plane.ai_usage_monthly WHERE id = :i"),
                {"i": rows[25]},
            ).rowcount
        assert deleted == 1
        assert _present(admin, tenant_id) == {rows[0], rows[1], rows[24]}
        # The owner is let through (it could drop the trigger anyway).
        with admin.begin() as conn:
            conn.execute(
                text("DELETE FROM control_plane.ai_usage_monthly WHERE id = :i"), {"i": rows[0]}
            )
        assert _present(admin, tenant_id) == {rows[1], rows[24]}
    finally:
        app.dispose()
        with admin.begin() as conn:
            conn.execute(
                text("DELETE FROM control_plane.ai_usage_monthly WHERE tenant_id = :t"),
                {"t": tenant_id},
            )
            conn.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": tenant_id})


def test_the_downgrade_revokes_delete_and_drops_the_trigger(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    try:
        command.downgrade(cfg, _PREVIOUS)
        assert not _can_delete(admin)
        assert _function(admin) is None
        with admin.connect() as conn:
            triggers = conn.execute(
                text(
                    "SELECT count(*) FROM pg_trigger "
                    "WHERE tgname = 'trg_ai_usage_monthly_refuse_recent_delete'"
                )
            ).scalar_one()
        assert triggers == 0
        command.upgrade(cfg, _REVISION)
        assert _can_delete(admin)
        assert _function(admin) is not None
    finally:
        command.upgrade(cfg, "head")
