"""Migration test for `e4b8c2d6f1a3` (ADR-0054 Phase AI-C): the AI
configuration tables, the minimum tenant AI policy tables, and the widened
`ck_platform_grants_permission`.

Asserts at head: the five global tables have no RLS and the runtime role
cannot delete from them; the three tenant tables have forced RLS and a
tenant policy; the CHECK accepts the four AI permissions and still refuses
an unknown one. Then: a downgrade refuses while an AI grant exists (by
design, nothing is deleted), and once no AI grant exists it removes exactly
these tables and restores the eighteen-permission CHECK; upgrade restores
everything.

**Destructive to schema state for its duration**: downgrades one revision
and re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
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
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError, ProgrammingError

from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "e4b8c2d6f1a3"  # pragma: allowlist secret
_PREVIOUS = "d3e9a1c47b20"  # pragma: allowlist secret
_GLOBAL = {
    "ai_providers",
    "ai_models",
    "ai_aliases",
    "ai_endpoint_trust",
    "ai_destination_policy",
}
_TENANT = {"ai_tenant_policies", "ai_tenant_use_case_grants", "ai_tenant_destination_grants"}
# Tables of later AI migrations, crossed by a downgrade from head.
_AI_D = {"ai_inference_attempts", "ai_tenant_preferences", "ai_model_prices"}
_AI_PERMISSIONS = (
    "platform.ai_config:read",
    "platform.ai_provider:manage",
    "platform.ai_endpoint_trust:manage",
    "platform.ai_policy:manage",
)


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
            conn.execute(text("SELECT 1 FROM core.platform_grants LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _tables(admin: Engine) -> set[str]:
    with admin.connect() as conn:
        return set(
            conn.execute(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'control_plane'"
                )
            ).scalars()
        )


def _app_role() -> str:
    from sqlalchemy.engine import make_url

    return make_url(get_database_config().url).username or "saas_os_app"


def test_the_tables_at_head(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    assert _GLOBAL | _TENANT <= _tables(admin)
    role = _app_role()
    with admin.connect() as conn:
        for table in sorted(_GLOBAL | _TENANT):
            qualified = f"control_plane.{table}"
            rls = conn.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE oid = CAST(:t AS regclass)"
                ),
                {"t": qualified},
            ).one()
            privileges = {
                p: conn.execute(
                    text("SELECT has_table_privilege(:r, CAST(:t AS regclass), :p)"),
                    {"r": role, "t": qualified, "p": p},
                ).scalar_one()
                for p in ("SELECT", "INSERT", "UPDATE", "DELETE")
            }
            if table in _TENANT:
                assert tuple(rls) == (True, True), table
                assert all(privileges.values()), (table, privileges)
                policies = conn.execute(
                    text(
                        "SELECT count(*) FROM pg_policies "
                        "WHERE schemaname = 'control_plane' AND tablename = :t"
                    ),
                    {"t": table},
                ).scalar_one()
                assert policies >= 1, table
            else:
                assert tuple(rls) == (False, False), table
                # At head the application role only reads the global tables:
                # f6a2c8e4b1d9 (ADR-0056) moved their writes to the
                # platform-configuration role.
                assert privileges == {
                    "SELECT": True,
                    "INSERT": False,
                    "UPDATE": False,
                    "DELETE": False,
                }, table


def _seed_operator(conn: Connection) -> uuid.UUID:
    user_id, operator_id = uuid.uuid4(), uuid.uuid4()
    conn.execute(text("INSERT INTO core.users (id) VALUES (:u)"), {"u": user_id})
    conn.execute(
        text("INSERT INTO core.platform_operators (id, user_id, status) VALUES (:o, :u, 'active')"),
        {"o": operator_id, "u": user_id},
    )
    return operator_id


def _grant(conn: Connection, operator_id: uuid.UUID, permission: str) -> None:
    conn.execute(
        text("INSERT INTO core.platform_grants (id, operator_id, permission) VALUES (:g, :o, :p)"),
        {"g": uuid.uuid4(), "o": operator_id, "p": permission},
    )


def _remove_operator(admin: Engine, operator_id: uuid.UUID) -> None:
    with admin.begin() as conn:
        conn.execute(
            text("DELETE FROM core.platform_grants WHERE operator_id = :o"), {"o": operator_id}
        )
        user_id = conn.execute(
            text("DELETE FROM core.platform_operators WHERE id = :o RETURNING user_id"),
            {"o": operator_id},
        ).scalar_one()
        conn.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": user_id})


def test_the_check_accepts_the_ai_permissions_and_refuses_an_unknown_one(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        trans = conn.begin()
        try:
            operator_id = _seed_operator(conn)
            for permission in _AI_PERMISSIONS:
                _grant(conn, operator_id, permission)
            with pytest.raises(IntegrityError), conn.begin_nested():
                # Q9: `platform.ai_usage:read` arrives with its operation (AI-D).
                _grant(conn, operator_id, "platform.ai_usage:write")
        finally:
            trans.rollback()


def test_downgrade_refuses_while_an_ai_grant_exists_then_round_trips(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    before = _tables(admin)
    with admin.connect() as conn:
        lingering = conn.execute(
            text(
                "SELECT g.permission, o.user_id, g.granted_by_user_id FROM core.platform_grants g "
                "JOIN core.platform_operators o ON o.id = g.operator_id "
                "WHERE g.permission LIKE 'platform.ai_%'"
            )
        ).all()
    assert lingering == [], f"a previous test left an AI platform grant behind: {lingering}"

    with admin.begin() as conn:
        operator_id = _seed_operator(conn)
        _grant(conn, operator_id, "platform.ai_policy:manage")
    try:
        with pytest.raises(DBAPIError):
            command.downgrade(cfg, _PREVIOUS)
        # Nothing was dropped and nothing was deleted: one transaction.
        assert _tables(admin) == before
        with admin.connect() as conn:
            kept = conn.execute(
                text("SELECT count(*) FROM core.platform_grants WHERE operator_id = :o"),
                {"o": operator_id},
            ).scalar_one()
        assert kept == 1
    finally:
        _remove_operator(admin, operator_id)

    try:
        command.downgrade(cfg, _PREVIOUS)
        # From head, the downgrade also crosses the later AI migrations.
        assert _tables(admin) == before - _GLOBAL - _TENANT - _AI_D
        with admin.connect() as conn:
            definition = conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname = 'ck_platform_grants_permission'"
                )
            ).scalar_one()
        assert "ai_" not in definition and "platform.authority:manage" in definition
        command.upgrade(cfg, _REVISION)
        assert _tables(admin) == before - _AI_D
    finally:
        command.upgrade(cfg, "head")
