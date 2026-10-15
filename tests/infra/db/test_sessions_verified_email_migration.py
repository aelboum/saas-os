"""Migration test for `3654bebb24c7` (ADR-0046): the nullable
`core.sessions.verified_email` column.

Additive only. The test asserts the column at head, that existing sessions
survive both directions with every other column intact and the new column
`NULL`, that the application role can write it, and that a downgrade
removes exactly that column.

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
_REVISION = "3654bebb24c7"  # pragma: allowlist secret
_PREVIOUS = "d7e4b2a91c36"  # pragma: allowlist secret


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


def _column(admin: Engine) -> tuple[str, str, int | None] | None:
    with admin.connect() as conn:
        row = conn.execute(
            text(
                "SELECT data_type, is_nullable, character_maximum_length "
                "FROM information_schema.columns WHERE table_schema = 'core' "
                "AND table_name = 'sessions' AND column_name = 'verified_email'"
            )
        ).one_or_none()
    return None if row is None else (row[0], row[1], row[2])


def _other_columns(admin: Engine) -> list[tuple[str, str]]:
    with admin.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = 'core' AND table_name = 'sessions' "
                "AND column_name <> 'verified_email' ORDER BY column_name"
            )
        ).all()
    return [(row[0], row[1]) for row in rows]


def test_the_column_is_a_nullable_varchar_320_at_head(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    assert _column(admin) == ("character varying", "YES", 320)


def test_the_application_role_writes_it_and_an_old_session_keeps_null(admin: Engine) -> None:
    command.upgrade(_config(), "head")
    user = create_user()
    try:
        with_email, _ = issue_session(user.id, verified_email=" Ada@Example.TEST ")
        without, _ = issue_session(user.id, lifetime=timedelta(minutes=5))
        with admin.connect() as conn:
            stored = dict(
                conn.execute(
                    text("SELECT id, verified_email FROM core.sessions WHERE user_id = :u"),
                    {"u": user.id},
                ).all()
            )
        assert stored == {with_email.id: "ada@example.test", without.id: None}
    finally:
        with admin.begin() as conn:
            conn.execute(text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": user.id})
            conn.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": user.id})


def test_downgrade_and_upgrade_change_only_the_column_and_keep_the_sessions(
    admin: Engine,
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    user = create_user()
    session, _ = issue_session(user.id, verified_email="kept@example.test")
    try:
        # The columns as this revision leaves them: later revisions add more.
        command.downgrade(cfg, _REVISION)
        others = _other_columns(admin)
        command.downgrade(cfg, _PREVIOUS)
        assert _column(admin) is None
        assert _other_columns(admin) == others
        command.upgrade(cfg, _REVISION)
        assert _column(admin) == ("character varying", "YES", 320)
        assert _other_columns(admin) == others
        with admin.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT user_id, expires_at > :now, verified_email FROM core.sessions "
                    "WHERE id = :s"
                ),
                {"s": session.id, "now": datetime.now(UTC)},
            ).one()
        # The session survived both directions; only the stored email is gone.
        assert (row[0], row[1], row[2]) == (user.id, True, None)
    finally:
        command.upgrade(cfg, "head")
        with admin.begin() as conn:
            conn.execute(text("DELETE FROM core.sessions WHERE user_id = :u"), {"u": user.id})
            conn.execute(text("DELETE FROM core.users WHERE id = :u"), {"u": user.id})
