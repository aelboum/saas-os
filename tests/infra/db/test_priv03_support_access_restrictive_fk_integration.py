"""PRIV-03 Phase P1 -- end-to-end proof, against a real PostgreSQL
instance, that `core.support_access_requests.tenant_id`'s foreign key to
`core.tenants.id` is restrictive (migration `f3a9c85e1b64`), not
`CASCADE` as it was originally created (`9aecff1d1135`): a tenant with a
support-access row can no longer be deleted, and the row itself is never
silently destroyed as a side effect of deleting its own tenant.

Marked `integration` and excluded from the default `pytest` run,
mirroring `tests/infra/db/test_func_export_removed_integration.py` and
`tests/infra/db/test_priv01_invitations_rls_integration.py` -- same
fixtures, same real-role setup.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration \\
        tests/infra/db/test_priv03_support_access_restrictive_fk_integration.py
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from saas_os.core.authority import UserCaller
from saas_os.core.identity.service import create_user
from saas_os.core.rbac.service import create_support_access_request
from saas_os.core.tenancy.service import create_tenant
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine
from saas_os.infra.db.migration_runner import (
    core_head_revision,
    current_core_revision,
    downgrade_core_migrations,
    run_core_migrations,
)
from saas_os.infra.db.session import build_session_factory, session_scope


def _admin_clear_audit_references(params: object, *, table: str) -> None:
    """Test cleanup only. Core writes its audit evidence in the same
    transaction as every authority change (ADR-0031), and `core.audit_log`
    rows reference `core.tenants`/`core.users` while the runtime role can
    never delete them -- so before a test deletes tenants or users, their
    audit rows are cleared with the privileged migrations role."""
    from sqlalchemy import text

    from saas_os.infra.db.config import get_migrations_database_config
    from saas_os.infra.db.engine import build_engine
    from saas_os.infra.db.session import build_session_factory, session_scope

    raw = params.values() if isinstance(params, dict) else [params]
    values: list[str] = []
    for value in raw:
        items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
        values.extend(str(item) for item in items)
    if table == "tenants":
        where = "tenant_id::text = ANY(:v) OR acting_as_tenant_id::text = ANY(:v)"
    else:
        where = "actor_user_id::text = ANY(:v)"
    engine = build_engine(get_migrations_database_config())
    try:
        with session_scope(session_factory=build_session_factory(engine)) as session:
            # Rows another open transaction already holds (e.g. a teardown that
            # deleted them itself, not yet committed) are being removed by it:
            # skip them rather than wait on that transaction.
            session.execute(
                text(
                    "DELETE FROM core.audit_log WHERE id IN (SELECT id FROM core.audit_log "
                    f"WHERE {where} FOR UPDATE SKIP LOCKED)"
                ),
                {"v": values},
            )
    finally:
        engine.dispose()


pytestmark = pytest.mark.integration

_PREVIOUS_REVISION = "cb7120cfa806"
_THIS_REVISION = "f3a9c85e1b64"


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        config = get_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL not configured for the integration test: {exc}")

    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first."
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


@pytest.fixture
def admin_session_factory() -> Iterator[sessionmaker[Session]]:
    engine = build_engine(get_migrations_database_config())
    try:
        yield build_session_factory(engine)
    finally:
        engine.dispose()


def _fk_delete_rule(admin_session_factory: sessionmaker[Session]) -> str:
    with session_scope(session_factory=admin_session_factory) as session:
        row = session.execute(
            text(
                "SELECT confdeltype FROM pg_constraint "
                "WHERE conname = 'support_access_requests_tenant_id_fkey'"
            )
        ).scalar_one()
        return row


def _make_tenant_with_support_request(tenant_name: str) -> tuple[uuid.UUID, uuid.UUID]:
    tenant = create_tenant(name=tenant_name)
    user = create_user()
    request = create_support_access_request(
        tenant_id=tenant.id,
        reason="PRIV-03 P1 regression test",
        requested_expires_at=datetime.now(UTC) + timedelta(hours=1),
        caller=UserCaller(user.id),
    )
    return tenant.id, request.id


def _cleanup(admin_session_factory: sessionmaker[Session], tenant_id: uuid.UUID) -> None:
    with session_scope(session_factory=admin_session_factory) as session:
        session.execute(
            text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
        )
        session.execute(
            text("DELETE FROM core.support_access_requests WHERE tenant_id = :t"),
            {"t": str(tenant_id)},
        )
    with session_scope() as session:
        _admin_clear_audit_references({"t": str(tenant_id)}, table="tenants")
        session.execute(text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)})


# --- 1. FK is restrictive after upgrade -------------------------------------


def test_support_access_requests_tenant_fk_is_restrictive_after_upgrade(
    admin_session_factory: sessionmaker[Session],
) -> None:
    """`confdeltype = 'a'` is Postgres's catalog code for `NO ACTION`
    (the restrictive default) -- `'c'` (`CASCADE`) is what this migration
    replaces."""
    assert _fk_delete_rule(admin_session_factory) == "a"


# --- 2. Deleting a tenant with a support-access row is rejected -------------


def test_deleting_a_tenant_with_a_support_access_row_is_rejected(
    admin_session_factory: sessionmaker[Session],
) -> None:
    tenant_id, _request_id = _make_tenant_with_support_request(
        f"priv03-p1-restrict-{uuid.uuid4().hex[:8]}"
    )
    try:
        # `create_support_access_request()` itself writes a `saas_os.core.audit_log`
        # row (already restrictively FK'd to `tenants` before this
        # migration) -- clear it first so the delete attempt below isolates
        # the `support_access_requests` FK specifically, rather than
        # failing on the pre-existing `audit_log` constraint instead.
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )

        with pytest.raises(IntegrityError, match="support_access_requests_tenant_id_fkey"):
            with session_scope() as session:
                _admin_clear_audit_references({"t": str(tenant_id)}, table="tenants")
                session.execute(
                    text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)}
                )
    finally:
        _cleanup(admin_session_factory, tenant_id)


# --- 3. Existing support-access rows remain intact after the failed delete --


def test_support_access_row_survives_the_rejected_tenant_delete(
    admin_session_factory: sessionmaker[Session],
) -> None:
    tenant_id, request_id = _make_tenant_with_support_request(
        f"priv03-p1-survive-{uuid.uuid4().hex[:8]}"
    )
    try:
        with session_scope(session_factory=admin_session_factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )

        with pytest.raises(IntegrityError, match="support_access_requests_tenant_id_fkey"):
            with session_scope() as session:
                _admin_clear_audit_references({"t": str(tenant_id)}, table="tenants")
                session.execute(
                    text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant_id)}
                )

        with session_scope(session_factory=admin_session_factory) as session:
            row = session.execute(
                text("SELECT id, tenant_id FROM core.support_access_requests WHERE id = :id"),
                {"id": str(request_id)},
            ).one_or_none()
        assert row is not None, "the support-access row was destroyed despite the rejected delete"
        assert row[1] == tenant_id
    finally:
        _cleanup(admin_session_factory, tenant_id)


# --- 4. Downgrade restores the original CASCADE behavior --------------------


def test_downgrade_restores_cascade_behavior(
    admin_session_factory: sessionmaker[Session],
) -> None:
    try:
        downgrade_core_migrations(_PREVIOUS_REVISION)
        assert current_core_revision() == _PREVIOUS_REVISION
        assert _fk_delete_rule(admin_session_factory) == "c"
    finally:
        run_core_migrations("head")
        assert current_core_revision() == core_head_revision()
        assert _fk_delete_rule(admin_session_factory) == "a"


# --- 5. No other FK behavior was changed by this migration ------------------


def test_no_other_tenant_fk_delete_rule_was_changed(
    admin_session_factory: sessionmaker[Session],
) -> None:
    """Spot-check every other tenant-referencing FK this migration must
    not have touched: the three already-CASCADE tables stay CASCADE, and
    a representative restrictive one stays restrictive."""
    with session_scope(session_factory=admin_session_factory) as session:
        result = session.execute(
            text(
                "SELECT conname, confdeltype FROM pg_constraint "
                "WHERE conname IN ("
                "  'delegation_grants_tenant_id_fkey',"
                "  'deny_grants_tenant_id_fkey',"
                "  'invitations_tenant_id_fkey',"
                "  'tenant_memberships_tenant_id_fkey',"
                "  'audit_log_tenant_id_fkey'"
                ")"
            )
        ).all()
        rows = {row[0]: row[1] for row in result}
    assert rows["delegation_grants_tenant_id_fkey"] == "c"
    assert rows["deny_grants_tenant_id_fkey"] == "c"
    assert rows["invitations_tenant_id_fkey"] == "c"
    assert rows["tenant_memberships_tenant_id_fkey"] == "a"
    assert rows["audit_log_tenant_id_fkey"] == "a"
