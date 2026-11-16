"""Audit identity phase P3a against a real PostgreSQL: tenant audit subject
references (`saas_os.core.audit_log.subjects`, migration `c7e3a9f2b4d8`;
docs/architecture/AUDIT-IDENTITY-P3-PLAN.md and
docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-PROPOSAL.md sections 4.3,
4.4 and 4.6).

- get-or-create returns one live reference per tenant, user and UTC day, and
  independent references in two tenants;
- a reference of tenant A means nothing in tenant B: refused by row-level
  security alone (no tenant predicate) and by the tenant predicate alone (RLS
  lifted), the two negative controls of proposal section 4.3, item 6; a
  get-or-create that names another tenant than the session's is refused;
- erasure writes the marker, unlinks the tenant's live links not covered by
  an active hold, keeps held ones, leaves other tenants alone, and a later
  write gets a reference that is born unlinked; `erase_user_identity()`
  records the counts, never a reference;
- an id that names no user, and a transaction that is not READ COMMITTED,
  get no reference (`AuditSubjectLinkUnavailableError`, naming no id);
- the runtime role cannot DELETE a link, cannot change any column but the
  three unlink columns, and a link only ever changes live -> unlinked.

Marked `integration`. The tables are emptied after every test body by
`tests/conftest.py`; the tenants and users made here are removed afterwards.
"""

from __future__ import annotations

import builtins
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError
from sqlalchemy.orm import Session

import saas_os.core.rbac  # noqa: F401 -- registers the mappers saas_os.core.audit_log references by name
from lifecycle_callers import PROVISIONING
from saas_os.core.audit_log import AuditSubjectLinkUnavailableError
from saas_os.core.audit_log.subjects import audit_subject_ref, erase_tenant_audit_subject
from saas_os.core.identity.erasure import erase_user_identity
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db import session_scope, tenant_session_scope
from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine, get_engine

pytestmark = pytest.mark.integration

_LINKS = "core.audit_subject_links"


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
            conn.execute(text(f"SELECT 1 FROM {_LINKS} LIMIT 1"))  # noqa: S608
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture
def world(admin: Engine) -> Iterator[tuple[builtins.list[uuid.UUID], builtins.list[uuid.UUID]]]:
    """Two tenants and two users; removed afterwards (the reference tables
    are emptied after the test body by `tests/conftest.py`)."""
    tenants = [create_tenant(f"p3a-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id for _ in (1, 2)]
    users = [uuid.uuid4(), uuid.uuid4()]
    with admin.begin() as conn:
        for user_id in users:
            conn.execute(text("INSERT INTO core.users (id) VALUES (:u)"), {"u": user_id})
    try:
        yield tenants, users
    finally:
        with admin.begin() as conn:
            ids = [str(t) for t in tenants]
            conn.execute(
                text(
                    "DELETE FROM core.audit_log WHERE tenant_id::text = ANY(:t) "
                    "OR acting_as_tenant_id::text = ANY(:t)"
                ),
                {"t": ids},
            )
            conn.execute(
                text("DELETE FROM core.platform_audit_log WHERE target_tenant_id::text = ANY(:t)"),
                {"t": ids},
            )
            conn.execute(text("DELETE FROM core.tenants WHERE id::text = ANY(:t)"), {"t": ids})
            conn.execute(
                text("DELETE FROM core.users WHERE id::text = ANY(:u)"),
                {"u": [str(u) for u in users]},
            )


def _ref(tenant: uuid.UUID, user: uuid.UUID) -> uuid.UUID:
    with tenant_session_scope(tenant) as session:
        return audit_subject_ref(session, tenant_id=tenant, user_id=user)


def _owner_rows(admin: Engine, tenant: uuid.UUID, sql: str, **params: object) -> list[tuple]:
    """Rows as the migrations role, in a transaction bound to `tenant`
    (FORCE RLS binds the owner too)."""
    with admin.begin() as conn:
        conn.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant)})
        return [tuple(row) for row in conn.execute(text(sql), params).all()]


def test_one_live_reference_per_tenant_user_and_day(
    admin: Engine, world: tuple[list[uuid.UUID], list[uuid.UUID]]
) -> None:
    (tenant_a, tenant_b), (user, other) = world
    first = _ref(tenant_a, user)
    assert _ref(tenant_a, user) == first  # the same day: the same reference
    assert _ref(tenant_a, other) != first  # another user
    in_b = _ref(tenant_b, user)
    assert in_b != first  # independent in another tenant
    assert _owner_rows(
        admin, tenant_a, f"SELECT user_id FROM {_LINKS} WHERE subject_ref = :r", r=first
    ) == [(user,)]


def test_a_reference_of_one_tenant_means_nothing_in_another(
    admin: Engine, world: tuple[list[uuid.UUID], list[uuid.UUID]]
) -> None:
    (tenant_a, tenant_b), (user, _) = world
    reference = _ref(tenant_a, user)
    # Row-level security alone: no tenant predicate, the runtime role bound
    # to tenant B. (Not the migrations role: a superuser bypasses RLS.)
    with tenant_session_scope(tenant_b) as session:
        assert (
            session.execute(
                text(f"SELECT user_id FROM {_LINKS} WHERE subject_ref = :r"), {"r": reference}
            ).all()
            == []
        )
    # The predicate alone: RLS lifted for one rolled-back transaction, the
    # query names tenant B, as every query in Core does.
    with admin.connect() as conn:
        trans = conn.begin()
        try:
            conn.execute(text(f"ALTER TABLE {_LINKS} NO FORCE ROW LEVEL SECURITY"))
            conn.execute(text(f"ALTER TABLE {_LINKS} DISABLE ROW LEVEL SECURITY"))
            assert conn.execute(
                text(f"SELECT user_id FROM {_LINKS} WHERE subject_ref = :r"), {"r": reference}
            ).all() == [(user,)]  # the control: the row is there without either layer
            assert (
                conn.execute(
                    text(
                        f"SELECT user_id FROM {_LINKS} "  # noqa: S608
                        "WHERE subject_ref = :r AND tenant_id = :t"
                    ),
                    {"r": reference, "t": tenant_b},
                ).all()
                == []
            )
        finally:
            trans.rollback()


def test_a_get_or_create_naming_another_tenant_is_refused(
    admin: Engine, world: tuple[list[uuid.UUID], list[uuid.UUID]]
) -> None:
    (tenant_a, tenant_b), (user, _) = world
    with pytest.raises(DBAPIError), tenant_session_scope(tenant_b) as session:
        audit_subject_ref(session, tenant_id=tenant_a, user_id=user)
    assert _owner_rows(admin, tenant_a, f"SELECT 1 FROM {_LINKS}") == []  # noqa: S608


def test_an_unknown_user_gets_no_reference_and_the_error_names_no_id(
    world: tuple[list[uuid.UUID], list[uuid.UUID]],
) -> None:
    (tenant_a, _), _ = world
    unknown = uuid.uuid4()
    with pytest.raises(AuditSubjectLinkUnavailableError) as refused:
        _ref(tenant_a, unknown)
    assert str(unknown) not in str(refused.value) and unknown.hex not in str(refused.value)


def test_a_transaction_that_is_not_read_committed_gets_no_reference(
    world: tuple[list[uuid.UUID], list[uuid.UUID]],
) -> None:
    (tenant_a, _), (user, _) = world
    engine = build_engine(get_database_config()).execution_options(
        isolation_level="REPEATABLE READ"
    )
    try:
        with Session(engine) as session, session.begin():
            session.execute(
                text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_a)}
            )
            with pytest.raises(AuditSubjectLinkUnavailableError):
                audit_subject_ref(session, tenant_id=tenant_a, user_id=user)
    finally:
        engine.dispose()


def test_erasure_unlinks_the_tenants_live_links_keeps_held_ones_and_leaves_others(
    admin: Engine, world: tuple[list[uuid.UUID], list[uuid.UUID]]
) -> None:
    (tenant_a, tenant_b), (user, other) = world
    live = _ref(tenant_a, user)
    in_b = _ref(tenant_b, user)
    others = _ref(tenant_a, other)
    # A held link of the same user (an older day), under an active hold.
    with admin.begin() as conn:
        conn.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_a)})
        held = conn.execute(
            text(
                f"INSERT INTO {_LINKS} (tenant_id, user_id, subject_day) "  # noqa: S608
                "VALUES (:t, :u, DATE '2026-01-05') RETURNING subject_ref"
            ),
            {"t": tenant_a, "u": user},
        ).scalar_one()
        # The platform row that placed the hold: migration `e1f5a8c3b7d9`
        # (phase P3c) refuses a tenant hold without it.
        hold_id, audit_id = uuid.uuid4(), uuid.uuid4()
        conn.execute(
            text(
                "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
                "target_type, target_id, target_tenant_id, outcome) VALUES (:a, 'system', "
                "'platform_bootstrap', 'platform.audit_identity.hold_place', "
                "'audit_identity_hold', :h, :t, 'success')"
            ),
            {"a": audit_id, "h": str(hold_id), "t": tenant_a},
        )
        conn.execute(
            text(
                "INSERT INTO core.audit_identity_holds (id, tenant_id, reference, from_day, "
                "to_day, placed_by_platform_audit_id) VALUES (:i, :t, 'LEGAL-P3A', "
                "DATE '2026-01-01', DATE '2026-01-31', :a)"
            ),
            {"i": hold_id, "t": tenant_a, "a": audit_id},
        )

    with tenant_session_scope(tenant_a) as session:
        counts = erase_tenant_audit_subject(session, tenant_id=tenant_a, user_id=user)
    assert (counts.links_unlinked, counts.links_kept_under_hold) == (1, 1)

    def linked(tenant: uuid.UUID, reference: uuid.UUID) -> object:
        return _owner_rows(
            admin, tenant, f"SELECT user_id FROM {_LINKS} WHERE subject_ref = :r", r=reference
        )[0][0]

    assert linked(tenant_a, live) is None  # unlinked
    assert linked(tenant_a, held) == user  # kept under the hold
    assert linked(tenant_a, others) == other  # another user: untouched
    assert linked(tenant_b, in_b) == user  # another tenant: untouched
    # A later write about the erased user gets a reference that names nobody.
    after = _ref(tenant_a, user)
    assert after not in (live, held)
    assert linked(tenant_a, after) is None
    # A rerun changes nothing.
    with tenant_session_scope(tenant_a) as session:
        again = erase_tenant_audit_subject(session, tenant_id=tenant_a, user_id=user)
    assert (again.links_unlinked, again.links_kept_under_hold) == (0, 1)


def test_identity_erasure_unlinks_each_given_tenant_and_records_counts_only(
    admin: Engine, world: tuple[list[uuid.UUID], list[uuid.UUID]]
) -> None:
    (tenant_a, tenant_b), (user, actor) = world
    reference = _ref(tenant_a, user)
    kept_in_b = _ref(tenant_b, user)

    result = erase_user_identity(user, [tenant_a], actor_user_id=actor)

    assert (result.tenant_references_unlinked, result.tenant_references_kept_under_hold) == (1, 0)
    assert _owner_rows(
        admin, tenant_a, f"SELECT user_id FROM {_LINKS} WHERE subject_ref = :r", r=reference
    ) == [(None,)]
    assert _owner_rows(
        admin, tenant_b, f"SELECT user_id FROM {_LINKS} WHERE subject_ref = :r", r=kept_in_b
    ) == [(user,)]  # not a tenant of this erasure
    rows = _owner_rows(
        admin,
        tenant_a,
        "SELECT metadata::text FROM core.audit_log "
        "WHERE tenant_id = :t AND action = 'identity.erasure_audit_references_unlinked'",
        t=tenant_a,
    )
    assert len(rows) == 1
    assert '"references_unlinked": 1' in rows[0][0] and str(reference) not in rows[0][0]


def test_the_runtime_role_cannot_delete_or_repoint_a_link(
    world: tuple[list[uuid.UUID], list[uuid.UUID]],
) -> None:
    (tenant_a, _), (user, other) = world
    reference = _ref(tenant_a, user)
    for statement, params in (
        (f"DELETE FROM {_LINKS} WHERE subject_ref = :r", {"r": reference}),
        (
            f"UPDATE {_LINKS} SET subject_day = DATE '2000-01-01' WHERE subject_ref = :r",
            {"r": reference},
        ),
        (f"UPDATE {_LINKS} SET user_id = :o WHERE subject_ref = :r", {"r": reference, "o": other}),
    ):
        with pytest.raises(DBAPIError), tenant_session_scope(tenant_a) as session:
            session.execute(text(statement), params)
    # The one designed change, live -> unlinked, is allowed; relinking is not.
    with tenant_session_scope(tenant_a) as session:
        session.execute(
            text(
                f"UPDATE {_LINKS} SET user_id = NULL, unlinked_at = now(), "  # noqa: S608
                "unlink_reason = 'erasure' WHERE subject_ref = :r"
            ),
            {"r": reference},
        )
    with (
        pytest.raises(DBAPIError, match="only ever changes"),
        tenant_session_scope(tenant_a) as session,
    ):
        session.execute(
            text(
                f"UPDATE {_LINKS} SET user_id = :u, unlinked_at = NULL, "  # noqa: S608
                "unlink_reason = NULL WHERE subject_ref = :r"
            ),
            {"r": reference, "u": user},
        )
    with session_scope() as session:  # untenanted: sees no tenant link
        assert session.execute(text(f"SELECT count(*) FROM {_LINKS}")).scalar_one() == 0  # noqa: S608
