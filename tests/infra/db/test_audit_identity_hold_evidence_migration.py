"""Migration test for `b6d2f8a4c1e7` (audit identity phase P2: every audit
identity hold change needs its platform audit evidence).

At head: a deferred constraint trigger on `core.platform_audit_identity_holds`
refuses, at commit and for every role, a hold whose placing audit id does not
name the matching successful `platform.audit_identity.hold_place` row of that
hold, and a release whose releasing audit id does not name the matching
`hold_release` row; a hold with its evidence commits. The function is not
`SECURITY DEFINER` and pins its search path. The downgrade drops the trigger
and its function (a hold without evidence then commits); the upgrade restores
them, and refuses while a row without evidence exists.

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
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError

from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "b6d2f8a4c1e7"  # pragma: allowlist secret
_PREVIOUS = "e8a3c6f1d9b4"  # pragma: allowlist secret
_FUNCTION = "platform_audit_identity_holds_evidence"
_PLACE = "platform.audit_identity.hold_place"
_RELEASE = "platform.audit_identity.hold_release"


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
            conn.execute(text("SELECT 1 FROM core.platform_audit_identity_holds LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture
def clean(admin: Engine) -> Iterator[None]:
    yield
    with admin.begin() as conn:
        conn.execute(text("DELETE FROM core.platform_audit_identity_holds"))
        conn.execute(
            text("DELETE FROM core.platform_audit_log WHERE target_type = 'audit_identity_hold'")
        )


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _audit_row(
    conn: Connection, action: str, target: uuid.UUID, outcome: str = "success"
) -> uuid.UUID:
    audit_id = uuid.uuid4()
    conn.execute(
        text(
            "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
            "target_type, target_id, outcome) VALUES (:i, 'system', 'platform_bootstrap', :a, "
            "'audit_identity_hold', :h, :o)"
        ),
        {"i": audit_id, "a": action, "h": str(target), "o": outcome},
    )
    return audit_id


def _hold(conn: Connection, hold_id: uuid.UUID, placed_by: uuid.UUID) -> None:
    conn.execute(
        text(
            "INSERT INTO core.platform_audit_identity_holds (id, reference, "
            "placed_by_platform_audit_id) VALUES (:i, :r, :p)"
        ),
        # One matter each: the active-hold unique index is not under test.
        {"i": hold_id, "r": f"LEGAL-{hold_id.hex[:8]}", "p": placed_by},
    )


def _release(conn: Connection, hold_id: uuid.UUID, released_by: uuid.UUID) -> None:
    conn.execute(
        text(
            "UPDATE core.platform_audit_identity_holds SET released_at = now(), "
            "released_by_platform_audit_id = :r WHERE id = :h"
        ),
        {"r": released_by, "h": hold_id},
    )


def _function(admin: Engine) -> tuple[bool, list[str] | None] | None:
    with admin.connect() as conn:
        row = conn.execute(
            text(
                "SELECT p.prosecdef, p.proconfig FROM pg_proc p JOIN pg_namespace n "
                "ON n.oid = p.pronamespace WHERE n.nspname = 'core' AND p.proname = :f"
            ),
            {"f": _FUNCTION},
        ).one_or_none()
    return None if row is None else (bool(row[0]), row[1])


def _sqlstate(error: DBAPIError) -> str | None:
    return getattr(error.orig, "sqlstate", None)


def test_at_head_a_hold_change_commits_only_with_its_evidence(admin: Engine, clean: None) -> None:
    command.upgrade(_config(), "head")
    assert _function(admin) == (False, ["search_path=pg_catalog"])

    # The hold first, its audit row second: the check runs at commit.
    hold_id = uuid.uuid4()
    with admin.begin() as conn:
        audit_id = uuid.uuid4()
        _hold(conn, hold_id, audit_id)
        conn.execute(
            text(
                "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
                "target_type, target_id, outcome) VALUES (:i, 'system', 'platform_bootstrap', "
                ":a, 'audit_identity_hold', :h, 'success')"
            ),
            {"i": audit_id, "a": _PLACE, "h": str(hold_id)},
        )

    # Evidence of another hold, of another action, or of a refusal.
    for action, outcome, other_target in (
        (_PLACE, "success", True),
        (_RELEASE, "success", False),
        (_PLACE, "denied", False),
    ):
        other = uuid.uuid4()
        with pytest.raises(DBAPIError) as refused, admin.begin() as conn:
            audit_id = _audit_row(conn, action, uuid.uuid4() if other_target else other, outcome)
            _hold(conn, other, audit_id)
        assert _sqlstate(refused.value) == "23503"

    # A release needs a release row of this hold.
    with pytest.raises(DBAPIError) as refused, admin.begin() as conn:
        _release(conn, hold_id, uuid.uuid4())
    assert _sqlstate(refused.value) == "23503"
    with admin.begin() as conn:
        _release(conn, hold_id, _audit_row(conn, _RELEASE, hold_id))


def test_the_downgrade_drops_the_check_and_the_upgrade_refuses_a_row_without_evidence(
    admin: Engine, clean: None
) -> None:
    cfg = _config()
    command.upgrade(cfg, "head")
    try:
        command.downgrade(cfg, _PREVIOUS)
        assert _function(admin) is None
        with admin.begin() as conn:
            _hold(conn, uuid.uuid4(), uuid.uuid4())  # no evidence: nothing checks it now
        with pytest.raises(DBAPIError):
            command.upgrade(cfg, _REVISION)
        assert _function(admin) is None
        with admin.begin() as conn:
            conn.execute(text("DELETE FROM core.platform_audit_identity_holds"))
        command.upgrade(cfg, _REVISION)
        assert _function(admin) is not None
    finally:
        command.upgrade(cfg, "head")
