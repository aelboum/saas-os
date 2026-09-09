"""infra/db session lifecycle tests (docs/IMPLEMENTATION-ROADMAP.md Phase
2.1). Uses an in-memory SQLite engine (stdlib `sqlite3`, no new dependency)
to exercise session_scope()'s generic commit/rollback control flow --
that behavior is plain SQLAlchemy Session semantics, not PostgreSQL-
specific, so it does not need a real PostgreSQL instance. See
test_db_integration.py for the real-PostgreSQL, `infra/db`-end-to-end
test the roadmap also requires.
"""

from __future__ import annotations

import pytest
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import create_engine, text


@pytest.fixture
def sqlite_session_factory():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE probe (id INTEGER PRIMARY KEY, value TEXT)"))
    return build_session_factory(engine)


def test_session_scope_commits_on_success(sqlite_session_factory) -> None:
    with session_scope(session_factory=sqlite_session_factory) as session:
        session.execute(text("INSERT INTO probe (id, value) VALUES (1, 'a')"))

    with session_scope(session_factory=sqlite_session_factory) as session:
        row = session.execute(text("SELECT value FROM probe WHERE id = 1")).one()
    assert row.value == "a"


def test_session_scope_rolls_back_on_exception(sqlite_session_factory) -> None:
    with pytest.raises(RuntimeError):
        with session_scope(session_factory=sqlite_session_factory) as session:
            session.execute(text("INSERT INTO probe (id, value) VALUES (2, 'b')"))
            raise RuntimeError("simulated failure mid-transaction")

    with session_scope(session_factory=sqlite_session_factory) as session:
        count = session.execute(text("SELECT COUNT(*) AS n FROM probe WHERE id = 2")).one()
    assert count.n == 0


def test_session_scope_closes_the_session(sqlite_session_factory) -> None:
    opened_session = None
    with session_scope(session_factory=sqlite_session_factory) as session:
        opened_session = session
    # SQLAlchemy raises if you try to use a closed session's connection
    # for a new operation outside its original transaction.
    assert not opened_session.in_transaction()


def test_session_scope_uses_the_default_factory_when_none_given(
    monkeypatch: pytest.MonkeyPatch, sqlite_session_factory
) -> None:
    """Non-vacuous: confirm session_scope() with *no* explicit factory
    really does go through get_session_factory(), not some other path.
    """
    import infra.db.session as session_module

    monkeypatch.setattr(session_module, "get_session_factory", lambda: sqlite_session_factory)

    with session_module.session_scope() as session:
        session.execute(text("INSERT INTO probe (id, value) VALUES (3, 'c')"))

    with session_scope(session_factory=sqlite_session_factory) as session:
        row = session.execute(text("SELECT value FROM probe WHERE id = 3")).one()
    assert row.value == "c"
