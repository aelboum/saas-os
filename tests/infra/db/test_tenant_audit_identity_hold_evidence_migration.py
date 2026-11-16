"""Migration test for `e1f5a8c3b7d9` (audit identity phase P3c: every tenant
audit identity hold change needs its platform audit evidence).

At head: a deferred constraint trigger on `core.audit_identity_holds`
refuses, at commit and for every role, a hold whose placing audit id does not
name the matching successful `platform.audit_identity.hold_place` row of that
hold *and tenant*, and a release whose releasing audit id does not name the
matching `hold_release` row; a hold with its evidence commits. The function
is not `SECURITY DEFINER` and pins its search path. The table keeps `ENABLE`
and `FORCE` row-level security after the upgrade, whose existing-row check
lifts it only inside its own transaction. The downgrade drops the trigger and
its function; the upgrade restores them, refuses while a row without evidence
exists, and then leaves row-level security forced.

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

import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from lifecycle_callers import PROVISIONING
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "e1f5a8c3b7d9"  # pragma: allowlist secret
_PREVIOUS = "d4f8b2e6a9c1"  # pragma: allowlist secret
_FUNCTION = "audit_identity_holds_evidence"
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
            conn.execute(text("SELECT 1 FROM core.audit_identity_holds LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture
def tenants(admin: Engine) -> Iterator[tuple[uuid.UUID, uuid.UUID]]:
    made = tuple(
        create_tenant(f"p3c-mig-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id for _ in (1, 2)
    )
    try:
        yield made[0], made[1]
    finally:
        command.upgrade(_config(), "head")
        ids = [str(t) for t in made]
        with admin.begin() as conn:
            conn.execute(text("TRUNCATE core.audit_identity_holds"))
            conn.execute(
                text("DELETE FROM core.platform_audit_log WHERE target_tenant_id::text = ANY(:t)"),
                {"t": ids},
            )
            conn.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id::text = ANY(:t)"), {"t": ids}
            )
            conn.execute(text("DELETE FROM core.tenants WHERE id::text = ANY(:t)"), {"t": ids})


def _config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _audit_row(
    conn: Connection,
    action: str,
    target: uuid.UUID,
    tenant: uuid.UUID,
    outcome: str = "success",
) -> uuid.UUID:
    audit_id = uuid.uuid4()
    conn.execute(
        text(
            "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
            "target_type, target_id, target_tenant_id, outcome) VALUES (:i, 'system', "
            "'platform_bootstrap', :a, 'audit_identity_hold', :h, :t, :o)"
        ),
        {"i": audit_id, "a": action, "h": str(target), "t": tenant, "o": outcome},
    )
    return audit_id


def _hold(conn: Connection, hold_id: uuid.UUID, tenant: uuid.UUID, placed_by: uuid.UUID) -> None:
    conn.execute(
        text(
            "INSERT INTO core.audit_identity_holds (id, tenant_id, reference, "
            "placed_by_platform_audit_id) VALUES (:i, :t, :r, :p)"
        ),
        # One matter each: the active-hold unique index is not under test.
        {"i": hold_id, "t": tenant, "r": f"LEGAL-{hold_id.hex[:8]}", "p": placed_by},
    )


def _release(conn: Connection, hold_id: uuid.UUID, released_by: uuid.UUID) -> None:
    conn.execute(
        text(
            "UPDATE core.audit_identity_holds SET released_at = now(), "
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


def _rls(admin: Engine) -> tuple[bool, bool]:
    with admin.connect() as conn:
        row = conn.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid = 'core.audit_identity_holds'::regclass"
            )
        ).one()
    return bool(row[0]), bool(row[1])


def _sqlstate(error: DBAPIError) -> str | None:
    return getattr(error.orig, "sqlstate", None)


def test_at_head_a_tenant_hold_change_commits_only_with_its_evidence(
    admin: Engine, tenants: tuple[uuid.UUID, uuid.UUID]
) -> None:
    tenant, other = tenants
    command.upgrade(_config(), "head")
    assert _function(admin) == (False, ["search_path=pg_catalog"])
    assert _rls(admin) == (True, True)

    # The hold first, its audit row second: the check runs at commit.
    hold_id = uuid.uuid4()
    with admin.begin() as conn:
        audit_id = uuid.uuid4()
        _hold(conn, hold_id, tenant, audit_id)
        conn.execute(
            text(
                "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
                "target_type, target_id, target_tenant_id, outcome) VALUES (:i, 'system', "
                "'platform_bootstrap', :a, 'audit_identity_hold', :h, :t, 'success')"
            ),
            {"i": audit_id, "a": _PLACE, "h": str(hold_id), "t": tenant},
        )

    # Evidence of another hold, of another tenant, of another action, or of a refusal.
    for action, outcome, other_target, evidence_tenant in (
        (_PLACE, "success", True, tenant),
        (_PLACE, "success", False, other),
        (_RELEASE, "success", False, tenant),
        (_PLACE, "denied", False, tenant),
    ):
        new = uuid.uuid4()
        with pytest.raises(DBAPIError) as refused, admin.begin() as conn:
            audit_id = _audit_row(
                conn, action, uuid.uuid4() if other_target else new, evidence_tenant, outcome
            )
            _hold(conn, new, tenant, audit_id)
        assert _sqlstate(refused.value) == "23503"

    # A release needs a release row of this hold and tenant.
    with pytest.raises(DBAPIError) as refused, admin.begin() as conn:
        _release(conn, hold_id, _audit_row(conn, _RELEASE, hold_id, other))
    assert _sqlstate(refused.value) == "23503"
    with admin.begin() as conn:
        _release(conn, hold_id, _audit_row(conn, _RELEASE, hold_id, tenant))


def test_the_downgrade_drops_the_check_and_the_upgrade_refuses_a_row_without_evidence(
    admin: Engine, tenants: tuple[uuid.UUID, uuid.UUID]
) -> None:
    tenant, _other = tenants
    cfg = _config()
    command.upgrade(cfg, "head")
    try:
        command.downgrade(cfg, _PREVIOUS)
        assert _function(admin) is None
        assert _rls(admin) == (True, True)
        with admin.begin() as conn:
            _hold(conn, uuid.uuid4(), tenant, uuid.uuid4())  # nothing checks it now
        with pytest.raises(DBAPIError):
            command.upgrade(cfg, _REVISION)
        # The refusal rolled back the whole upgrade, the lift of RLS included.
        assert _function(admin) is None
        assert _rls(admin) == (True, True)
        with admin.begin() as conn:
            conn.execute(text("TRUNCATE core.audit_identity_holds"))
        command.upgrade(cfg, _REVISION)
        assert _function(admin) is not None
        assert _rls(admin) == (True, True)
    finally:
        command.upgrade(cfg, "head")
