"""Migration test for `e2b7c4d9a1f6` (audit identity phase P1: the platform
audit subject reference tables), against real PostgreSQL.

- the three tables are global with the tenant-context exclusion policy
  (ENABLE + FORCE), named foreign keys onto `core.users` (`NO ACTION`) and
  the CHECKs, unique indexes and triggers of the reviewed DDL
  (docs/architecture/AUDIT-P1-SQL-REVIEW.md);
- the runtime role may SELECT and INSERT, may UPDATE only the three unlink
  columns of a link and the two release columns of a hold, and never DELETE
  or TRUNCATE;
- a link only ever changes live -> unlinked and a released hold never
  changes, for every role including the owner;
- the upgrade bounds its wait for the lock on `core.users` (5s) and the
  downgrade locks the three tables before it counts rows, so an insert in
  flight cannot slip in between the check and the DROP;
- the downgrade refuses while any of the three tables holds a row (and
  changes nothing), then drops exactly those tables; the platform audit log
  is byte-identical before and after (existing rows and digests untouched);
  a re-upgrade recreates them empty.

**Destructive to schema state for its duration**: downgrades one revision
and re-applies it on whatever database `MIGRATIONS_DATABASE_URL` points at.
Disposable databases only. Marked `integration`. Everything it creates is
removed in `finally` blocks.
"""

from __future__ import annotations

import threading
import time
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
_REVISION = "e2b7c4d9a1f6"  # pragma: allowlist secret
_PREVIOUS = "f0cc2e656d79"  # pragma: allowlist secret
_LINKS = "core.platform_audit_subject_links"
_ERASURES = "core.platform_audit_subject_erasures"
_HOLDS = "core.platform_audit_identity_holds"
_TABLES = (_LINKS, _ERASURES, _HOLDS)
_DENIED = (ProgrammingError, DBAPIError)


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


@pytest.fixture(scope="module")
def runtime() -> Iterator[Engine]:
    engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _exists(admin: Engine, table: str) -> bool:
    with admin.connect() as conn:
        return conn.execute(text("SELECT to_regclass(:t) IS NOT NULL"), {"t": table}).scalar_one()


def _count(admin: Engine, table: str) -> int:
    with admin.connect() as conn:
        return conn.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()  # noqa: S608


def _user(admin: Engine) -> uuid.UUID:
    user_id = uuid.uuid4()
    with admin.begin() as conn:
        conn.execute(text("INSERT INTO core.users (id) VALUES (:u)"), {"u": user_id})
    return user_id


def _clear(admin: Engine, users: list[uuid.UUID]) -> None:
    with admin.begin() as conn:
        if _exists(admin, _LINKS):
            conn.execute(text("TRUNCATE " + ", ".join(_TABLES)))
        if users:
            conn.execute(text("DELETE FROM core.users WHERE id = ANY(:u)"), {"u": users})


def _link(conn: Connection, user_id: uuid.UUID | None, day: str = "2026-01-01") -> uuid.UUID:
    if user_id is None:
        return conn.execute(
            text(
                f"INSERT INTO {_LINKS} (user_id, subject_day, unlinked_at, unlink_reason) "  # noqa: S608
                f"VALUES (NULL, DATE '{day}', now(), 'erasure') RETURNING subject_ref"
            )
        ).scalar_one()
    return conn.execute(
        text(
            f"INSERT INTO {_LINKS} (user_id, subject_day) "  # noqa: S608
            f"VALUES (:u, DATE '{day}') RETURNING subject_ref"
        ),
        {"u": user_id},
    ).scalar_one()


def _hold(
    conn: Connection, reference: str = "LEGAL-1", subject_ref: uuid.UUID | None = None
) -> uuid.UUID:
    hold_id = uuid.uuid4()
    conn.execute(
        text(
            f"INSERT INTO {_HOLDS} (id, reference, subject_ref, placed_by_platform_audit_id) "  # noqa: S608
            "VALUES (:i, :r, :s, :a)"
        ),
        {"i": hold_id, "r": reference, "s": subject_ref, "a": uuid.uuid4()},
    )
    return hold_id


def test_the_tables_are_global_excluded_from_tenant_scope_and_named_as_reviewed(
    admin: Engine,
) -> None:
    command.upgrade(_config(), "head")
    with admin.connect() as conn:
        for table in _TABLES:
            flags = conn.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE oid = CAST(:t AS regclass)"
                ),
                {"t": table},
            ).one()
            assert tuple(flags) == (True, True), table
            policy = conn.execute(
                text("SELECT qual FROM pg_policies WHERE schemaname = 'core' AND tablename = :t"),
                {"t": table.split(".")[1]},
            ).scalar_one()
            assert "app.tenant_id" in policy and "IS NULL" in policy, table
            columns = {
                row[0]
                for row in conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'core' AND table_name = :t"
                    ),
                    {"t": table.split(".")[1]},
                )
            }
            assert "tenant_id" not in columns, table  # global, owned by no tenant
        constraints = {
            row[0]: row[1]
            for row in conn.execute(
                text(
                    "SELECT conname, confdeltype FROM pg_constraint "
                    "WHERE conrelid = ANY(ARRAY[CAST(:a AS regclass), CAST(:b AS regclass), "
                    "CAST(:c AS regclass)]) AND contype = 'f'"
                ),
                {"a": _LINKS, "b": _ERASURES, "c": _HOLDS},
            )
        }
        assert constraints == {
            "fk_platform_audit_subject_links_user_id": "a",
            "fk_platform_audit_subject_erasures_user_id": "a",
        }
        index = conn.execute(
            text(
                "SELECT indexdef FROM pg_indexes WHERE schemaname = 'core' "
                "AND indexname = 'uq_platform_audit_identity_holds_active'"
            )
        ).scalar_one()
        assert "NULLS NOT DISTINCT" in index and "released_at IS NULL" in index
        live = conn.execute(
            text(
                "SELECT indexdef FROM pg_indexes WHERE schemaname = 'core' "
                "AND indexname = 'uq_platform_audit_subject_links_live'"
            )
        ).scalar_one()
        assert "UNIQUE" in live and "user_id IS NOT NULL" in live
        for function in (
            "platform_audit_subject_links_one_way",
            "platform_audit_identity_holds_release_once",
        ):
            security_definer, config = conn.execute(
                text(
                    "SELECT prosecdef, proconfig FROM pg_proc p JOIN pg_namespace n "
                    "ON n.oid = p.pronamespace WHERE n.nspname = 'core' AND proname = :f"
                ),
                {"f": function},
            ).one()
            assert security_definer is False  # not SECURITY DEFINER
            assert config == ["search_path=pg_catalog"]  # a fixed search_path


def test_the_runtime_role_has_exactly_the_designed_privileges(
    admin: Engine, runtime: Engine
) -> None:
    command.upgrade(_config(), "head")
    role = runtime.url.username
    with admin.connect() as conn:
        table_privileges = {
            table: {
                privilege: conn.execute(
                    text("SELECT has_table_privilege(:r, :t, :p)"),
                    {"r": role, "t": table, "p": privilege},
                ).scalar_one()
                for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
            }
            for table in _TABLES
        }
        updatable = {
            (table, column)
            for table in _TABLES
            for (column,) in conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'core' AND table_name = :t"
                ),
                {"t": table.split(".")[1]},
            )
            if conn.execute(
                text("SELECT has_column_privilege(:r, :t, :c, 'UPDATE')"),
                {"r": role, "t": table, "c": column},
            ).scalar_one()
        }
    for table in _TABLES:
        assert table_privileges[table] == {
            "SELECT": True,
            "INSERT": True,
            "UPDATE": False,
            "DELETE": False,
            "TRUNCATE": False,
        }, table
    assert updatable == {
        (_LINKS, "user_id"),
        (_LINKS, "unlinked_at"),
        (_LINKS, "unlink_reason"),
        (_HOLDS, "released_at"),
        (_HOLDS, "released_by_platform_audit_id"),
    }


def test_the_runtime_role_cannot_update_or_delete_what_it_must_not(
    admin: Engine, runtime: Engine
) -> None:
    command.upgrade(_config(), "head")
    users: list[uuid.UUID] = []
    try:
        user_id = _user(admin)
        users.append(user_id)
        with admin.begin() as conn:
            ref = _link(conn, user_id)
            conn.execute(text(f"INSERT INTO {_ERASURES} (user_id) VALUES (:u)"), {"u": user_id})  # noqa: S608
            hold = _hold(conn)
        refused = [
            f"UPDATE {_LINKS} SET subject_day = DATE '2000-01-01' WHERE subject_ref = :r",
            f"UPDATE {_LINKS} SET created_at = now() WHERE subject_ref = :r",
            f"UPDATE {_LINKS} SET subject_ref = gen_random_uuid() WHERE subject_ref = :r",
            f"DELETE FROM {_LINKS} WHERE subject_ref = :r",
            f"UPDATE {_ERASURES} SET erased_at = now() WHERE user_id = :u",
            f"DELETE FROM {_ERASURES} WHERE user_id = :u",
            f"UPDATE {_HOLDS} SET reference = 'OTHER' WHERE id = :h",
            f"UPDATE {_HOLDS} SET placed_by_platform_audit_id = gen_random_uuid() WHERE id = :h",
            f"DELETE FROM {_HOLDS} WHERE id = :h",
        ]
        for statement in refused:
            with runtime.connect() as conn:
                trans = conn.begin()
                try:
                    with pytest.raises(_DENIED, match="permission denied"):
                        conn.execute(text(statement), {"r": ref, "u": user_id, "h": hold})
                finally:
                    trans.rollback()
        for table in _TABLES:
            with runtime.connect() as conn:
                trans = conn.begin()
                try:
                    with pytest.raises(_DENIED, match="permission denied"):
                        conn.execute(text(f"TRUNCATE {table}"))
                finally:
                    trans.rollback()
        # The designed writes work: unlink a link, release a hold, add a marker.
        with runtime.begin() as conn:
            conn.execute(
                text(
                    f"UPDATE {_LINKS} SET user_id = NULL, unlinked_at = now(), "  # noqa: S608
                    "unlink_reason = 'expiry' WHERE subject_ref = :r"
                ),
                {"r": ref},
            )
            conn.execute(
                text(
                    f"UPDATE {_HOLDS} SET released_at = now(), "  # noqa: S608
                    "released_by_platform_audit_id = :a WHERE id = :h"
                ),
                {"a": uuid.uuid4(), "h": hold},
            )
    finally:
        _clear(admin, users)


def test_a_link_only_goes_from_live_to_unlinked_and_a_released_hold_never_changes(
    admin: Engine,
) -> None:
    command.upgrade(_config(), "head")
    users: list[uuid.UUID] = []
    try:
        first, second = _user(admin), _user(admin)
        users += [first, second]
        with admin.connect() as conn:
            trans = conn.begin()
            try:
                live = _link(conn, first)
                with pytest.raises(IntegrityError, match="live to unlinked"), conn.begin_nested():
                    conn.execute(
                        text(f"UPDATE {_LINKS} SET user_id = :u WHERE subject_ref = :r"),  # noqa: S608
                        {"u": second, "r": live},  # re-pointed at another user
                    )
                with pytest.raises(IntegrityError), conn.begin_nested():
                    conn.execute(
                        text(  # unlinked without a reason: the pairing CHECK
                            f"UPDATE {_LINKS} SET user_id = NULL, unlinked_at = now() "  # noqa: S608
                            "WHERE subject_ref = :r"
                        ),
                        {"r": live},
                    )
                with pytest.raises(IntegrityError), conn.begin_nested():
                    conn.execute(
                        text(  # an unknown reason
                            f"UPDATE {_LINKS} SET user_id = NULL, unlinked_at = now(), "  # noqa: S608
                            "unlink_reason = 'other' WHERE subject_ref = :r"
                        ),
                        {"r": live},
                    )
                conn.execute(
                    text(
                        f"UPDATE {_LINKS} SET user_id = NULL, unlinked_at = now(), "  # noqa: S608
                        "unlink_reason = 'erasure' WHERE subject_ref = :r"
                    ),
                    {"r": live},
                )
                for change in (
                    "user_id = :u, unlinked_at = NULL, unlink_reason = NULL",  # relinked
                    "unlink_reason = 'expiry'",
                    "unlinked_at = now() + interval '1 day'",
                ):
                    with (
                        pytest.raises(IntegrityError, match="live to unlinked"),
                        conn.begin_nested(),
                    ):
                        conn.execute(
                            text(f"UPDATE {_LINKS} SET {change} WHERE subject_ref = :r"),  # noqa: S608
                            {"u": first, "r": live},
                        )
                # A day's live slot is free once its link is unlinked.
                _link(conn, first)
                with pytest.raises(IntegrityError), conn.begin_nested():
                    _link(conn, first)  # one live link per user and day
                # Born-unlinked rows (an erased subject) are outside the index.
                _link(conn, None)
                _link(conn, None)
                with pytest.raises(IntegrityError), conn.begin_nested():
                    conn.execute(
                        text(f"INSERT INTO {_LINKS} (user_id, subject_day) VALUES (NULL, now())")  # noqa: S608
                    )  # NULL user without unlinked_at
                with pytest.raises(IntegrityError), conn.begin_nested():
                    _link(conn, uuid.uuid4(), "2026-01-02")  # no such user
                # Holds: one active hold per reference and subject, NULL counted
                # as one value; a release is one-way, even for the owner role.
                _hold(conn)
                with pytest.raises(IntegrityError), conn.begin_nested():
                    _hold(conn)
                _hold(conn, "LEGAL-2")
                _hold(conn, "LEGAL-1", subject_ref=live)
                with pytest.raises((IntegrityError, DBAPIError)), conn.begin_nested():
                    _hold(conn, "John Smith")
                conn.execute(
                    text(
                        f"UPDATE {_HOLDS} SET released_at = now(), "  # noqa: S608
                        "released_by_platform_audit_id = :a "
                        "WHERE reference = 'LEGAL-1' AND subject_ref IS NULL"
                    ),
                    {"a": uuid.uuid4()},
                )
                _hold(conn)  # re-placed after the release
                with pytest.raises(IntegrityError, match="never changed"), conn.begin_nested():
                    conn.execute(
                        text(
                            f"UPDATE {_HOLDS} SET reference = 'LEGAL-9' "  # noqa: S608
                            "WHERE released_at IS NOT NULL"
                        )
                    )
            finally:
                trans.rollback()
    finally:
        _clear(admin, users)


def _audit_fingerprint(admin: Engine) -> tuple[int, str]:
    with admin.connect() as conn:
        return tuple(  # type: ignore[return-value]
            conn.execute(
                text(
                    "SELECT count(*), coalesce(md5(string_agg(t::text, '|' ORDER BY id)), '') "
                    "FROM core.platform_audit_log t"
                )
            ).one()
        )


def test_downgrade_refuses_while_any_table_has_a_row_and_leaves_existing_audit_rows_alone(
    admin: Engine,
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    users: list[uuid.UUID] = []
    legacy_id = uuid.uuid4()
    try:
        user_id = _user(admin)
        users.append(user_id)
        # A row written before the mechanism: a raw target id, kept as it is
        # (decision D5); the migration changes no audit row and no digest.
        with admin.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, "
                    "action, target_type, target_id, outcome) VALUES (:i, 'system', "
                    "'platform_bootstrap', 'platform.user.read', 'user', :t, 'success')"
                ),
                {"i": legacy_id, "t": str(user_id)},
            )
        before = _audit_fingerprint(admin)
        digests = _count(admin, "core.audit_digests")
        seeds = {
            _LINKS: lambda c: _link(c, user_id),
            _ERASURES: lambda c: c.execute(
                text(f"INSERT INTO {_ERASURES} (user_id) VALUES (:u)"),
                {"u": user_id},  # noqa: S608
            ),
            _HOLDS: lambda c: _hold(c),
        }
        try:
            for table, seed in seeds.items():
                with admin.begin() as conn:
                    seed(conn)
                # A row exists: the downgrade refuses and nothing changes.
                with pytest.raises(DBAPIError, match="refusing to drop it"):
                    command.downgrade(cfg, _PREVIOUS)
                for name in _TABLES:
                    assert _exists(admin, name)
                assert _count(admin, table) == 1
                with admin.begin() as conn:
                    conn.execute(text(f"TRUNCATE {table}"))  # noqa: S608
            # Empty: it drops exactly the three tables and their functions.
            command.downgrade(cfg, _PREVIOUS)
            for name in _TABLES:
                assert not _exists(admin, name)
            with admin.connect() as conn:
                functions = conn.execute(
                    text(
                        "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = "
                        "p.pronamespace WHERE n.nspname = 'core' AND proname LIKE "
                        "'platform_audit_%'"
                    )
                ).scalar_one()
            assert functions == 0
            assert _audit_fingerprint(admin) == before
            command.upgrade(cfg, _REVISION)
            for name in _TABLES:
                assert _exists(admin, name)
                assert _count(admin, name) == 0
            assert _audit_fingerprint(admin) == before
            assert _count(admin, "core.audit_digests") == digests
        finally:
            command.upgrade(cfg, "head")
    finally:
        with admin.begin() as conn:
            conn.execute(
                text("DELETE FROM core.platform_audit_log WHERE id = :i"), {"i": legacy_id}
            )
        _clear(admin, users)


def test_the_downgrade_locks_the_tables_before_it_counts_so_an_insert_in_flight_is_not_lost(
    admin: Engine,
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    users: list[uuid.UUID] = []
    outcome: list[BaseException | None] = []
    try:
        user_id = _user(admin)
        users.append(user_id)

        def downgrade() -> None:
            try:
                command.downgrade(cfg, _PREVIOUS)
                outcome.append(None)
            except BaseException as exc:  # noqa: BLE001
                outcome.append(exc)

        holder = admin.connect()
        try:
            transaction = holder.begin()
            _link(holder, user_id)  # in flight: not committed, invisible to a count
            worker = threading.Thread(target=downgrade)
            worker.start()
            time.sleep(1.5)
            # Blocked on the table lock, not past the check: nothing was dropped.
            assert worker.is_alive()
            assert _exists(admin, _LINKS)
            transaction.commit()
        finally:
            holder.close()
        worker.join(timeout=30)
        assert not worker.is_alive()
        # The lock was granted after the commit, so the count saw the row.
        assert len(outcome) == 1
        assert isinstance(outcome[0], DBAPIError)
        assert "refusing to drop it" in str(outcome[0])
        for name in _TABLES:
            assert _exists(admin, name)
        assert _count(admin, _LINKS) == 1
    finally:
        command.upgrade(cfg, "head")
        _clear(admin, users)


def test_the_upgrade_gives_up_on_a_lock_it_cannot_get_within_the_timeout(
    admin: Engine,
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    command.downgrade(cfg, _PREVIOUS)
    outcome: list[BaseException | None] = []
    started = time.monotonic()
    try:

        def upgrade() -> None:
            try:
                command.upgrade(cfg, _REVISION)
                outcome.append(None)
            except BaseException as exc:  # noqa: BLE001
                outcome.append(exc)

        holder = admin.connect()
        try:
            transaction = holder.begin()
            holder.execute(text("LOCK TABLE core.users IN ACCESS EXCLUSIVE MODE"))
            worker = threading.Thread(target=upgrade)
            worker.start()
            # Hold the lock well past the 5s timeout.
            time.sleep(9)
            transaction.rollback()
        finally:
            holder.close()
        worker.join(timeout=30)
        assert not worker.is_alive()
        assert len(outcome) == 1
        assert isinstance(outcome[0], DBAPIError)
        assert "lock timeout" in str(outcome[0]).lower()
        assert not _exists(admin, _LINKS)
        assert time.monotonic() - started < 40
    finally:
        command.upgrade(cfg, "head")
