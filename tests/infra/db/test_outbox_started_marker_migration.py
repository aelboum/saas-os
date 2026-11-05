"""Migration test for `0420025c3b4b` and `f0cc2e656d79` (crash recovery D4:
the outbox started marker; design pull request #195, section 4a; review
and reproduction pull request #200; owner decisions D1 to D3 of
2026-11-02, D4 approved for implementation on 2026-11-03), against real
PostgreSQL.

- at head: both columns nullable without a default, the pair check
  validated, the application role covered by the table grant;
- populated data: the B-only and the A downgrades keep every row and do not
  rewrite the table; the A downgrade loses the marker values (accepted
  limitation); the re-upgrade brings back empty columns;
- A behind an open reader fails on its 5 s `lock_timeout` and changes
  nothing; B blocked past 5 s fails, leaves the database at A with the
  check `NOT VALID` (still enforced), and a re-run applies only B; B on a
  violating row fails with `CheckViolation` and a re-run after the fix
  succeeds.

**Destructive to schema state for its duration**: downgrades to
`c3f9e1a7b5d2` and re-applies, on the database `MIGRATIONS_DATABASE_URL`
points at. Disposable databases only. Marked `integration`. Every row it
creates is removed in a `finally` block, and every test ends at head.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from lifecycle_callers import PROVISIONING
from saas_os.core.outbox import append_event
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.session import tenant_session_scope

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_A = "0420025c3b4b"  # pragma: allowlist secret
_B = "f0cc2e656d79"  # pragma: allowlist secret
_BEFORE = "c3f9e1a7b5d2"  # pragma: allowlist secret
_CHECK = "ck_outbox_events_external_started_pair"
_COLUMNS = ("external_started_at", "external_started_claim")


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
            conn.execute(text("SELECT 1 FROM core.outbox_events LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _state(admin: Engine) -> dict[str, Any]:
    with admin.connect() as conn:
        stamp = conn.execute(text("SELECT version_num FROM alembic_version_saas_os")).scalar_one()
        columns = {
            name: (nullable, default)
            for name, nullable, default in conn.execute(
                text(
                    "SELECT column_name, is_nullable, column_default "
                    "FROM information_schema.columns WHERE table_schema = 'core' "
                    "AND table_name = 'outbox_events' AND column_name = ANY(:c)"
                ),
                {"c": list(_COLUMNS)},
            )
        }
        check = conn.execute(
            text(
                "SELECT convalidated, pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = 'core.outbox_events'::regclass AND conname = :n"
            ),
            {"n": _CHECK},
        ).one_or_none()
        filenode = conn.execute(
            text("SELECT pg_relation_filenode('core.outbox_events')")
        ).scalar_one()
        rows = conn.execute(text("SELECT count(*) FROM core.outbox_events")).scalar_one()
    return {
        "stamp": stamp,
        "columns": columns,
        "check": None if check is None else tuple(check),
        "filenode": filenode,
        "rows": rows,
    }


@pytest.fixture
def at_head(admin: Engine) -> Iterator[Config]:
    cfg = _config()
    command.upgrade(cfg, "head")
    # These tests pin the state at `_B` itself. A later migration (audit
    # identity P1, `e2b7c4d9a1f6`) moved head past it: step back to `_B`
    # (a no-op while it is head) and end at head again.
    command.downgrade(cfg, _B)
    try:
        yield cfg
    finally:
        command.upgrade(cfg, "head")


@pytest.fixture
def events(admin: Engine, at_head: Config) -> Iterator[dict[str, uuid.UUID]]:
    """One tenant with three events at head: a pending event claimed by
    claim C1 and marked by it, a dead-lettered event that kept its marker,
    and one with no marker."""
    tenant_id = create_tenant(f"d4-mig-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id
    ids: dict[str, uuid.UUID] = {"tenant": tenant_id, "claim": uuid.uuid4()}
    with tenant_session_scope(tenant_id) as session:
        for name in ("pending", "dead", "plain"):
            ids[name] = append_event(
                session,
                tenant_id=tenant_id,
                event_type="probe.migration",
                aggregate_type="probe",
                aggregate_id=name,
                payload={"n": name},
            )
    with admin.begin() as conn:
        conn.execute(
            text(
                "UPDATE core.outbox_events SET claim_token = :c, attempts = 1, "
                "next_attempt_at = now() + interval '5 minutes', "
                "external_started_at = now(), external_started_claim = :c WHERE id = :i"
            ),
            {"c": ids["claim"], "i": ids["pending"]},
        )
        conn.execute(
            text(
                "UPDATE core.outbox_events SET status = 'dead_lettered', attempts = 1, "
                "last_error = 'CrashAfterStart: outcome unknown; not retried automatically', "
                "external_started_at = now(), external_started_claim = :c WHERE id = :i"
            ),
            {"c": uuid.uuid4(), "i": ids["dead"]},
        )
    try:
        yield ids
    finally:
        command.upgrade(_config(), "head")
        params = {"t": tenant_id}
        with admin.begin() as conn:
            conn.execute(text("DELETE FROM core.outbox_events WHERE tenant_id = :t"), params)
            conn.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t OR acting_as_tenant_id = :t"),
                params,
            )
            conn.execute(text("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t"), params)
            conn.execute(
                text("DELETE FROM core.platform_audit_log WHERE target_tenant_id = :t"), params
            )
            conn.execute(text("DELETE FROM core.tenants WHERE id = :t"), params)


def _markers(admin: Engine, ids: dict[str, uuid.UUID]) -> dict[str, tuple[object, ...]]:
    with admin.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT id, status, claim_token, external_started_claim "
                "FROM core.outbox_events WHERE tenant_id = :t"
            ),
            {"t": ids["tenant"]},
        ).all()
    names = {v: k for k, v in ids.items()}
    return {names[r[0]]: tuple(r[1:]) for r in rows}


def _markers_without_columns(admin: Engine, ids: dict[str, uuid.UUID]) -> dict[str, object]:
    with admin.connect() as conn:
        rows = conn.execute(
            text("SELECT id, status, claim_token FROM core.outbox_events WHERE tenant_id = :t"),
            {"t": ids["tenant"]},
        ).all()
    names = {v: k for k, v in ids.items()}
    return {names[r[0]]: (r[1], r[2]) for r in rows}


def test_head_has_both_columns_and_a_validated_pair_check(admin: Engine, at_head: Config) -> None:
    state = _state(admin)
    assert state["stamp"] == _B
    assert state["columns"] == {c: ("YES", None) for c in _COLUMNS}
    assert state["check"] == (
        True,
        "CHECK (((external_started_at IS NULL) = (external_started_claim IS NULL)))",
    )
    role = make_url(get_database_config().url).username
    with admin.connect() as conn:
        for column in _COLUMNS:
            for privilege in ("SELECT", "INSERT", "UPDATE"):
                assert conn.execute(
                    text("SELECT has_column_privilege(:r, 'core.outbox_events', :c, :p)"),
                    {"r": role, "c": column, "p": privilege},
                ).scalar_one(), (column, privilege)
        attacl = conn.execute(
            text(
                "SELECT attacl FROM pg_attribute WHERE attrelid = 'core.outbox_events'::regclass "
                "AND attname = ANY(:c)"
            ),
            {"c": list(_COLUMNS)},
        ).scalars()
        assert list(attacl) == [None, None]  # the table grant, no column grant


def test_downgrades_keep_every_row_and_lose_only_the_marker_values(
    admin: Engine, at_head: Config, events: dict[str, uuid.UUID]
) -> None:
    before = _state(admin)
    marked = _markers(admin, events)
    assert marked["pending"] == ("pending", events["claim"], events["claim"])
    assert marked["dead"][0] == "dead_lettered" and marked["dead"][2] is not None
    assert marked["plain"] == ("pending", None, None)

    command.downgrade(at_head, _A)  # B: stamp only
    state = _state(admin)
    assert state["stamp"] == _A
    assert state["check"] is not None and state["check"][0] is True  # no "un-validate"
    assert (state["rows"], state["filenode"]) == (before["rows"], before["filenode"])
    assert _markers(admin, events) == marked

    command.downgrade(at_head, _BEFORE)  # A: drops the check and both columns
    state = _state(admin)
    assert state["stamp"] == _BEFORE
    assert (state["columns"], state["check"]) == ({}, None)
    assert (state["rows"], state["filenode"]) == (before["rows"], before["filenode"])
    assert _markers_without_columns(admin, events) == {
        k: v[:2] for k, v in marked.items()
    }  # every row kept, status and claim unchanged

    command.upgrade(at_head, _B)
    state = _state(admin)
    assert state["stamp"] == _B and state["check"] is not None and state["check"][0] is True
    assert (state["rows"], state["filenode"]) == (before["rows"], before["filenode"])
    after = _markers(admin, events)
    assert {k: v[:2] for k, v in after.items()} == {k: v[:2] for k, v in marked.items()}
    assert all(v[2] is None for v in after.values())  # the marker values are gone


def _hold(admin: Engine, statement: str) -> Connection:
    conn = admin.connect()
    conn.execute(text(statement))
    return conn


def test_a_behind_an_open_reader_fails_on_its_lock_timeout_and_changes_nothing(
    admin: Engine, at_head: Config
) -> None:
    command.downgrade(at_head, _BEFORE)
    reader = _hold(admin, "SELECT count(*) FROM core.outbox_events")  # AccessShareLock, open
    try:
        started = time.monotonic()
        with pytest.raises(DBAPIError, match="lock timeout"):
            command.upgrade(at_head, _B)
        waited = time.monotonic() - started
    finally:
        reader.rollback()
        reader.close()
    assert 4.5 <= waited <= 30, waited
    state = _state(admin)
    assert (state["stamp"], state["columns"], state["check"]) == (_BEFORE, {}, None)


def test_b_blocked_past_its_lock_timeout_leaves_a_and_a_rerun_applies_only_b(
    admin: Engine, at_head: Config, events: dict[str, uuid.UUID]
) -> None:
    command.downgrade(at_head, _BEFORE)
    command.upgrade(at_head, _A)
    assert _state(admin)["check"] == (
        False,
        "CHECK (((external_started_at IS NULL) = (external_started_claim IS NULL))) NOT VALID",
    )
    blocker = _hold(admin, "LOCK TABLE core.outbox_events IN SHARE UPDATE EXCLUSIVE MODE")
    try:
        with pytest.raises(DBAPIError, match="lock timeout"):
            command.upgrade(at_head, _B)
    finally:
        blocker.rollback()
        blocker.close()
    state = _state(admin)
    assert state["stamp"] == _A
    assert state["check"] is not None and state["check"][0] is False
    # NOT VALID is still enforced for every write.
    with admin.connect() as conn, pytest.raises(DBAPIError, match=_CHECK):
        conn.execute(
            text("UPDATE core.outbox_events SET external_started_at = now() WHERE id = :i"),
            {"i": events["plain"]},
        )
    command.upgrade(at_head, _B)
    state = _state(admin)
    assert state["stamp"] == _B and state["check"] is not None and state["check"][0] is True


def test_b_on_a_violating_row_fails_and_succeeds_after_the_row_is_fixed(
    admin: Engine, at_head: Config, events: dict[str, uuid.UUID]
) -> None:
    command.downgrade(at_head, _A)
    with admin.begin() as conn:
        # Only possible by hand while the check is absent (#195 4a.11).
        conn.execute(text(f"ALTER TABLE core.outbox_events DROP CONSTRAINT {_CHECK}"))
        conn.execute(
            text("UPDATE core.outbox_events SET external_started_claim = NULL WHERE id = :i"),
            {"i": events["dead"]},
        )
        conn.execute(
            text(
                f"ALTER TABLE core.outbox_events ADD CONSTRAINT {_CHECK} CHECK "
                "((external_started_at IS NULL) = (external_started_claim IS NULL)) NOT VALID"
            )
        )
    with pytest.raises(DBAPIError, match="is violated by some row"):
        command.upgrade(at_head, _B)
    assert _state(admin)["stamp"] == _A
    with admin.connect() as conn:
        found = conn.execute(
            text(
                "SELECT id FROM core.outbox_events "
                "WHERE (external_started_at IS NULL) <> (external_started_claim IS NULL)"
            )
        ).scalars()
        assert list(found) == [events["dead"]]
    with admin.begin() as conn:
        conn.execute(
            text(
                "UPDATE core.outbox_events SET external_started_at = NULL, "
                "external_started_claim = NULL WHERE id = :i"
            ),
            {"i": events["dead"]},
        )
    command.upgrade(at_head, _B)
    state = _state(admin)
    assert state["stamp"] == _B and state["check"] is not None and state["check"][0] is True
