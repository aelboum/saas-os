"""Migration test for `b3d5f7a9c2e4` (outbox decision brief Q2, option 2A;
ADR-0045 amendment of 2026-10-31): `ck_platform_grants_permission` accepts
`platform.outbox:replay` at head and still refuses an unknown permission; a
downgrade refuses while a grant of it exists (by design, nothing is
deleted), and once none exists restores the twenty-three-permission CHECK;
upgrade restores it.

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
_REVISION = "b3d5f7a9c2e4"  # pragma: allowlist secret
_PREVIOUS = "f6a2c8e4b1d9"  # pragma: allowlist secret
_PERMISSION = "platform.outbox:replay"


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


def _definition(admin: Engine) -> str:
    with admin.connect() as conn:
        return conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname = 'ck_platform_grants_permission'"
            )
        ).scalar_one()


def test_the_check_accepts_the_replay_permission_and_refuses_an_unknown_one(
    admin: Engine,
) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        trans = conn.begin()
        try:
            operator_id = _seed_operator(conn)
            _grant(conn, operator_id, _PERMISSION)
            with pytest.raises(IntegrityError), conn.begin_nested():
                _grant(conn, operator_id, "platform.outbox:purge")
        finally:
            trans.rollback()


def test_downgrade_refuses_while_a_grant_exists_then_restores_the_previous_check(
    admin: Engine,
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    with admin.connect() as conn:
        lingering = conn.execute(
            text("SELECT count(*) FROM core.platform_grants WHERE permission = :p"),
            {"p": _PERMISSION},
        ).scalar_one()
    assert lingering == 0, "a previous test left a platform.outbox:replay grant behind"

    with admin.begin() as conn:
        operator_id = _seed_operator(conn)
        _grant(conn, operator_id, _PERMISSION)
    try:
        with pytest.raises(DBAPIError):
            command.downgrade(cfg, _PREVIOUS)
        assert _PERMISSION in _definition(admin)  # one transaction: nothing changed
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
        definition = _definition(admin)
        assert "outbox" not in definition and "platform.authority:manage" in definition
        assert "platform.ai_usage:read" in definition
        command.upgrade(cfg, _REVISION)
        assert _PERMISSION in _definition(admin)
    finally:
        command.upgrade(cfg, "head")
