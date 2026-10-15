"""Migration test for `b5d2f7a9c3e1` (ADR-0049): `core.sessions.multi_factor`
and `core.sessions.provider_authenticated_at`.

Additive only. The test asserts both columns at head, that the application
role writes them through `issue_session()`, that an existing session
survives both directions with every other column intact and the new
columns at their defaults, and that a downgrade removes exactly them.

**Destructive to schema state for its duration**: downgrades one revision
and re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
Disposable databases only. Marked `integration`.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError, ProgrammingError

from saas_os.core.identity.service import create_user
from saas_os.core.identity.sessions import issue_session
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "b5d2f7a9c3e1"  # pragma: allowlist secret
_PREVIOUS = "a8c3e5f1d204"  # pragma: allowlist secret


@pytest.fixture(scope="module")
def admin() -> Iterator[Engine]:
    get_migrations_database_config.cache_clear()
    get_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_migrations_database_config()
        get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"database not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.sessions LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


_NEW = ("multi_factor", "provider_authenticated_at")


def _columns(admin: Engine) -> dict[str, tuple[str, str, str | None]]:
    with admin.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT column_name, data_type, is_nullable, column_default "
                "FROM information_schema.columns WHERE table_schema = 'core' "
                "AND table_name = 'sessions'"
            )
        ).all()
    return {row[0]: (row[1], row[2], row[3]) for row in rows}


def _others(admin: Engine) -> dict[str, tuple[str, str, str | None]]:
    return {k: v for k, v in _columns(admin).items() if k not in _NEW}


def test_the_columns_at_head(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    columns = _columns(admin)
    assert columns["multi_factor"] == ("boolean", "NO", "false")
    assert columns["provider_authenticated_at"][:2] == ("timestamp with time zone", "YES")


def test_issue_session_writes_them_and_defaults_hold(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    user = create_user()
    at = datetime(2026, 10, 15, 8, 0, tzinfo=UTC)
    try:
        with_evidence, _ = issue_session(user.id, multi_factor=True, provider_authenticated_at=at)
        without, _ = issue_session(user.id)
        with admin.connect() as conn:
            stored = {
                row[0]: (row[1], row[2])
                for row in conn.execute(
                    text(
                        "SELECT id, multi_factor, provider_authenticated_at "
                        "FROM core.sessions WHERE user_id = :u"
                    ),
                    {"u": user.id},
                ).all()
            }
        assert stored == {with_evidence.id: (True, at), without.id: (False, None)}
    finally:
        with admin.begin() as conn:
            conn.execute(text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": user.id})
            conn.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": user.id})


def test_downgrade_and_upgrade_change_only_the_columns(admin: Engine) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    others = _others(admin)
    user = create_user()
    session, _ = issue_session(user.id, multi_factor=True, lifetime=timedelta(minutes=5))
    try:
        command.downgrade(cfg, _PREVIOUS)
        assert not set(_NEW) & set(_columns(admin))
        assert _others(admin) == others
        command.upgrade(cfg, _REVISION)
        assert _others(admin) == others
        with admin.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT user_id, multi_factor, provider_authenticated_at "
                    "FROM core.sessions WHERE id = :s"
                ),
                {"s": session.id},
            ).one()
        # The session survived; the evidence went back to its defaults.
        assert (row[0], row[1], row[2]) == (user.id, False, None)
    finally:
        command.upgrade(cfg, "head")
        with admin.begin() as conn:
            conn.execute(text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": user.id})
            conn.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": user.id})
