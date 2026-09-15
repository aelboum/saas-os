"""PRIV-03 Phase P11 (privacy re-audit RA-07, finding 1): `record()` never
lets a correlation id the `core.audit_log.correlation_id` column cannot
hold reach the database, against a real PostgreSQL instance.

The audit reproduced the gap: `api/middleware.py` accepted an `X-Request-ID`
of up to 128 characters, `record()` did not validate `correlation_id`, and
the column is `VARCHAR(100)` -- so an audited RBAC denial carrying a 101-
to 128-character client header failed with
`psycopg.errors.StringDataRightTruncation`, turned into HTTP 500, and lost
its own audit record. These tests pin the Core boundary independently of
the middleware: an explicit over-long id fails closed with the typed
`InvalidActionOrResourceError` before any write; an over-long *ambient* id
(bound by whatever produced the context) is treated as absent so the
record is still written; the 100-character boundary itself is accepted.

Marked `integration`, mirroring `test_audit_log_integration.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/audit_log/test_correlation_id_bound_integration.py
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from core.audit_log.errors import InvalidActionOrResourceError
from core.audit_log.models import ActorType, AuditOutcome
from core.audit_log.service import list as list_entries
from core.audit_log.service import record
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope
from sqlalchemy import text

import core.rbac  # noqa: F401 -- registers the mappers core.audit_log references by name
from core.tenancy import create_tenant
from infra.observability import bind_correlation_context

pytestmark = pytest.mark.integration

_LIMIT = 100


@pytest.fixture(autouse=True)
def _require_reachable_database() -> None:
    get_database_config.cache_clear()
    get_migrations_database_config.cache_clear()
    get_engine.cache_clear()
    try:
        get_database_config()
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"DATABASE_URL/MIGRATIONS_DATABASE_URL not configured: {exc}")
    probe_engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.audit_log LIMIT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL/core.audit_log not reachable: {exc}")
    finally:
        probe_engine.dispose()


@pytest.fixture
def tenant_id() -> Iterator[uuid.UUID]:
    tenant = create_tenant(f"priv03-p11-{uuid.uuid4().hex[:8]}")
    try:
        yield tenant.id
    finally:
        # Audit rows are undeletable by the runtime role by design: clean
        # up through the privileged migrations role, like every audit test.
        admin_engine = build_engine(get_migrations_database_config())
        try:
            with session_scope(session_factory=build_session_factory(admin_engine)) as session:
                session.execute(
                    text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant.id)}
                )
                session.execute(
                    text("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t"),
                    {"t": str(tenant.id)},
                )
                session.execute(
                    text("DELETE FROM core.tenants WHERE id = :t"), {"t": str(tenant.id)}
                )
        finally:
            admin_engine.dispose()


def _record(tenant_id: uuid.UUID, **kwargs: object):
    return record(
        tenant_id=tenant_id,
        actor_type=ActorType.SYSTEM,
        action="ra07.correlation_bound",
        resource_type="t",
        outcome=AuditOutcome.DENIED,
        **kwargs,  # type: ignore[arg-type]
    )


def test_explicit_correlation_id_at_the_limit_is_stored_verbatim(tenant_id: uuid.UUID) -> None:
    entry = _record(tenant_id, correlation_id="c" * _LIMIT)
    assert entry.correlation_id is not None
    assert entry.correlation_id == "c" * _LIMIT
    assert len(entry.correlation_id) == _LIMIT


@pytest.mark.parametrize("length", [_LIMIT + 1, 128, 1000])
def test_explicit_over_long_correlation_id_fails_closed_before_any_write(
    length: int, tenant_id: uuid.UUID
) -> None:
    """The typed, pre-database rejection every other over-long field gets --
    never a `StringDataRightTruncation` escaping from the write, and never
    a truncated id silently stored."""
    with pytest.raises(InvalidActionOrResourceError, match="correlation_id"):
        _record(tenant_id, correlation_id="x" * length)
    assert list_entries(tenant_id, limit=10) == []  # nothing reached the table


@pytest.mark.parametrize("length", [_LIMIT + 1, 128])
def test_over_long_ambient_correlation_id_is_dropped_and_the_record_is_still_written(
    length: int, tenant_id: uuid.UUID
) -> None:
    """The ambient id is not this caller's argument: it was bound by the
    request/job context. The audit write must survive it -- the security
    decision being recorded matters more than its correlation pointer."""
    with bind_correlation_context(request_id="a" * length):
        entry = _record(tenant_id)
    assert entry.correlation_id is None
    stored = list_entries(tenant_id, limit=10)
    assert len(stored) == 1
    assert stored[0].correlation_id is None


def test_ambient_correlation_id_at_the_limit_is_still_picked_up(tenant_id: uuid.UUID) -> None:
    with bind_correlation_context(request_id="b" * _LIMIT):
        entry = _record(tenant_id)
    assert entry.correlation_id == "b" * _LIMIT


def test_stored_correlation_ids_never_exceed_the_column_width(tenant_id: uuid.UUID) -> None:
    """Whatever path a value took, no stored id is wider than the column
    (`VARCHAR(100)`): the bound is enforced before the database, the
    database never has to truncate or reject."""
    _record(tenant_id, correlation_id="c" * _LIMIT)
    with bind_correlation_context(request_id="a" * 128):
        _record(tenant_id)
    with bind_correlation_context(request_id="d" * 64):
        _record(tenant_id)
    for entry in list_entries(tenant_id, limit=10):
        assert entry.correlation_id is None or len(entry.correlation_id) <= _LIMIT
