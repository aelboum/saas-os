"""Migration, privilege, constraint and policy tests for `c4a9e1f07b52`
(ADR-0045 Phase B: `core.platform_operators`, `core.platform_grants`,
`core.platform_audit_log`), against a real PostgreSQL.

What is proven here, each as the role that matters:

- the migration is reversible and re-appliable, and leaves the previous
  head intact;
- the runtime role's privileges on each table are exactly the narrowed set,
  and PostgreSQL itself rejects the statements that were revoked;
- the tenant-context exclusion policy behaves as ADR-0045 section 9b states
  for every state of `app.tenant_id` (never set, empty, a tenant's UUID, a
  malformed value, cleared again);
- a `FOR SHARE` lock taken before a tenant scope is bound is still held
  after the scope is left;
- the partial unique indexes and CHECK constraints hold.

The policy is defence in depth. Nothing here is a test of authorization:
an untenanted transaction of the runtime role sees every platform row, and
that is asserted, not hidden.

**Destructive**: downgrades past, then re-applies, `c4a9e1f07b52` on
whatever database `MIGRATIONS_DATABASE_URL` points at. Disposable databases
only. Marked `integration`, excluded from the default `pytest` run.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError, ProgrammingError

from saas_os.infra.db.config import get_database_config, get_migrations_database_config
from saas_os.infra.db.engine import build_engine

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "c4a9e1f07b52"  # pragma: allowlist secret
_PREVIOUS = "aa43b942bf93"  # pragma: allowlist secret
_TABLES = ("platform_operators", "platform_grants", "platform_audit_log")
_SET_TENANT = "SELECT set_config('app.tenant_id', :v, true)"


@pytest.fixture(scope="module")
def admin() -> Iterator[Engine]:
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured: {exc}")
    engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM core.platform_operators LIMIT 1"))
    except (OperationalError, ProgrammingError) as exc:
        engine.dispose()
        pytest.skip(f"PostgreSQL not reachable or not migrated to head: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def app(admin: Engine) -> Iterator[Engine]:
    get_database_config.cache_clear()
    engine = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    yield engine
    engine.dispose()


def _alembic_config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _exists(admin: Engine, table: str) -> bool:
    with admin.connect() as conn:
        return bool(
            conn.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'core' AND table_name = :t)"
                ),
                {"t": table},
            ).scalar_one()
        )


def _runtime_privileges(admin: Engine, app: Engine, table: str) -> set[str]:
    with app.connect() as conn:
        role = conn.execute(text("SELECT current_user")).scalar_one()
    with admin.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT privilege_type FROM information_schema.role_table_grants "
                "WHERE table_schema = 'core' AND table_name = :t AND grantee = :r"
            ),
            {"t": table, "r": role},
        ).scalars()
        return set(rows)


class Seed:
    """One user, one operator, one grant and one audit row, inserted with
    the privileged role (which is not subject to row-level security) and
    removed again at teardown (the runtime role cannot delete them)."""

    def __init__(self, admin: Engine) -> None:
        self.admin = admin
        self.user_id = uuid.uuid4()
        self.operator_id = uuid.uuid4()
        self.grant_id = uuid.uuid4()
        self.audit_id = uuid.uuid4()
        self.extra_users: list[uuid.UUID] = []
        with admin.begin() as conn:
            conn.execute(text("INSERT INTO core.users (id) VALUES (:u)"), {"u": self.user_id})
            conn.execute(
                text(
                    "INSERT INTO core.platform_operators (id, user_id, status) "
                    "VALUES (:o, :u, 'active')"
                ),
                {"o": self.operator_id, "u": self.user_id},
            )
            conn.execute(
                text(
                    "INSERT INTO core.platform_grants (id, operator_id, permission) "
                    "VALUES (:g, :o, 'platform.authority:manage')"
                ),
                {"g": self.grant_id, "o": self.operator_id},
            )
            conn.execute(
                text(
                    "INSERT INTO core.platform_audit_log "
                    "(id, actor_type, actor_user_id, action, target_type, outcome) "
                    "VALUES (:a, 'user', :u, 'platform.test.seed', 'operator', 'success')"
                ),
                {"a": self.audit_id, "u": self.user_id},
            )

    def user(self) -> uuid.UUID:
        user_id = uuid.uuid4()
        with self.admin.begin() as conn:
            conn.execute(text("INSERT INTO core.users (id) VALUES (:u)"), {"u": user_id})
        self.extra_users.append(user_id)
        return user_id

    def cleanup(self) -> None:
        users = [self.user_id, *self.extra_users]
        with self.admin.begin() as conn:
            conn.execute(
                text("DELETE FROM core.platform_audit_log WHERE actor_user_id = ANY(:u)"),
                {"u": users},
            )
            conn.execute(
                text(
                    "DELETE FROM core.platform_grants WHERE operator_id IN "
                    "(SELECT id FROM core.platform_operators WHERE user_id = ANY(:u))"
                ),
                {"u": users},
            )
            conn.execute(
                text("DELETE FROM core.platform_operators WHERE user_id = ANY(:u)"), {"u": users}
            )
            conn.execute(text("DELETE FROM core.users WHERE id = ANY(:u)"), {"u": users})


@pytest.fixture
def seed(admin: Engine) -> Iterator[Seed]:
    world = Seed(admin)
    try:
        yield world
    finally:
        world.cleanup()


def _counts(conn, seed: Seed) -> tuple[int, int, int]:  # type: ignore[no-untyped-def]
    return (
        conn.execute(
            text("SELECT count(*) FROM core.platform_operators WHERE id = :i"),
            {"i": seed.operator_id},
        ).scalar_one(),
        conn.execute(
            text("SELECT count(*) FROM core.platform_grants WHERE id = :i"), {"i": seed.grant_id}
        ).scalar_one(),
        conn.execute(
            text("SELECT count(*) FROM core.platform_audit_log WHERE id = :i"),
            {"i": seed.audit_id},
        ).scalar_one(),
    )


# --- migration cycle ---------------------------------------------------------


def test_upgrade_downgrade_upgrade_cycle_is_reversible(admin: Engine, app: Engine) -> None:
    cfg = _alembic_config()
    command.upgrade(cfg, "head")
    assert all(_exists(admin, table) for table in _TABLES)

    command.downgrade(cfg, _PREVIOUS)
    assert not any(_exists(admin, table) for table in _TABLES)
    # The previous head's own structures are untouched.
    assert _exists(admin, "tenants") and _exists(admin, "users") and _exists(admin, "audit_log")
    with admin.connect() as conn:
        leftover = conn.execute(
            text("SELECT count(*) FROM pg_policies WHERE policyname LIKE '%_no_tenant_context'")
        ).scalar_one()
    assert leftover == 0

    command.upgrade(cfg, _REVISION)
    assert all(_exists(admin, table) for table in _TABLES)
    with admin.connect() as conn:
        flags = conn.execute(
            text(
                "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'core' AND relname = ANY(:t)"
            ),
            {"t": list(_TABLES)},
        ).all()
    assert sorted(tuple(row) for row in flags) == sorted((t, True, True) for t in _TABLES)
    assert _runtime_privileges(admin, app, "platform_audit_log") == {"SELECT", "INSERT"}
    # Later revisions exist since ADR-0045 Phase C: leave the database at head.
    command.upgrade(cfg, "head")


def test_no_platform_table_has_a_tenant_id_column(admin: Engine) -> None:
    with admin.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT table_name, column_name FROM information_schema.columns "
                "WHERE table_schema = 'core' AND table_name = ANY(:t)"
            ),
            {"t": list(_TABLES)},
        ).all()
    columns = {(row[0], row[1]) for row in rows}
    assert not any(column == "tenant_id" for _, column in columns)
    assert ("platform_audit_log", "target_tenant_id") in columns


# --- privileges --------------------------------------------------------------


def test_runtime_role_privileges_are_exactly_the_narrowed_set(admin: Engine, app: Engine) -> None:
    """Default privileges in `core` grant SELECT, INSERT, UPDATE, DELETE on
    every new table; the migration must have revoked the rest."""
    assert _runtime_privileges(admin, app, "platform_operators") == {"SELECT", "INSERT", "UPDATE"}
    assert _runtime_privileges(admin, app, "platform_grants") == {"SELECT", "INSERT", "UPDATE"}
    assert _runtime_privileges(admin, app, "platform_audit_log") == {"SELECT", "INSERT"}


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM core.platform_operators WHERE id = :i",
        "DELETE FROM core.platform_grants WHERE id = :i",
        "DELETE FROM core.platform_audit_log WHERE id = :i",
        "UPDATE core.platform_audit_log SET outcome = 'denied' WHERE id = :i",
        "TRUNCATE core.platform_audit_log",
        "TRUNCATE core.platform_grants CASCADE",
    ],
)
def test_postgresql_rejects_revoked_statements_for_the_runtime_role(
    app: Engine, seed: Seed, statement: str
) -> None:
    with app.connect() as conn, conn.begin():
        with pytest.raises(ProgrammingError) as excinfo:
            conn.execute(text(statement), {"i": seed.operator_id} if ":i" in statement else {})
        assert "permission denied" in str(excinfo.value)


def test_runtime_role_can_insert_and_update_authority_rows_untenanted(
    app: Engine, seed: Seed
) -> None:
    """The statements Core needs do work, with no tenant bound."""
    with app.connect() as conn, conn.begin() as tx:
        conn.execute(
            text("UPDATE core.platform_operators SET status = 'suspended' WHERE id = :i"),
            {"i": seed.operator_id},
        )
        conn.execute(
            text("UPDATE core.platform_grants SET revoked_at = now() WHERE id = :i"),
            {"i": seed.grant_id},
        )
        conn.execute(
            text(
                "INSERT INTO core.platform_audit_log "
                "(id, actor_type, system_authority, action, target_type, outcome) "
                "VALUES (:a, 'system', 'platform_bootstrap', 'platform.test', 'operator', "
                "'success')"
            ),
            {"a": uuid.uuid4()},
        )
        conn.execute(
            text("SELECT id FROM core.platform_operators WHERE id = :i FOR SHARE"),
            {"i": seed.operator_id},
        )
        tx.rollback()


# --- tenant-context exclusion policy, as the runtime role --------------------


def test_never_set_tenant_context_sees_and_writes_platform_rows(app: Engine, seed: Seed) -> None:
    """A fresh connection that never set `app.tenant_id`."""
    fresh = build_engine(get_database_config(), connect_args={"connect_timeout": 1})
    try:
        with fresh.connect() as conn, conn.begin() as tx:
            assert conn.execute(
                text("SELECT current_setting('app.tenant_id', true)")
            ).scalar_one() in (None, "")
            assert _counts(conn, seed) == (1, 1, 1)
            tx.rollback()
    finally:
        fresh.dispose()


def test_empty_tenant_context_after_a_tenant_transaction_sees_platform_rows(
    app: Engine, seed: Seed
) -> None:
    """PostgreSQL resets a transaction-local setting to the empty string,
    not to unset, when the transaction that set it ends. The same pooled
    connection must then see platform rows again."""
    with app.connect() as conn:  # one connection, two consecutive transactions
        with conn.begin():
            conn.execute(text(_SET_TENANT), {"v": str(uuid.uuid4())})
            assert _counts(conn, seed) == (0, 0, 0)
        with conn.begin():
            setting = conn.execute(text("SELECT current_setting('app.tenant_id', true)"))
            assert setting.scalar_one() == ""
            assert _counts(conn, seed) == (1, 1, 1)


def test_tenant_bound_transaction_sees_no_platform_rows(app: Engine, seed: Seed) -> None:
    with app.connect() as conn, conn.begin() as tx:
        conn.execute(text(_SET_TENANT), {"v": str(uuid.uuid4())})
        assert _counts(conn, seed) == (0, 0, 0)
        tx.rollback()


def test_tenant_bound_transaction_cannot_update_platform_rows(
    admin: Engine, app: Engine, seed: Seed
) -> None:
    """An UPDATE under the policy matches no row -- nothing changes."""
    with app.connect() as conn, conn.begin():
        conn.execute(text(_SET_TENANT), {"v": str(uuid.uuid4())})
        updated = conn.execute(
            text("UPDATE core.platform_operators SET status = 'revoked' WHERE id = :i"),
            {"i": seed.operator_id},
        ).rowcount
        revoked = conn.execute(
            text("UPDATE core.platform_grants SET revoked_at = now() WHERE id = :i"),
            {"i": seed.grant_id},
        ).rowcount
    assert (updated, revoked) == (0, 0)
    with admin.connect() as conn:
        assert (
            conn.execute(
                text("SELECT status FROM core.platform_operators WHERE id = :i"),
                {"i": seed.operator_id},
            ).scalar_one()
            == "active"
        )
        assert (
            conn.execute(
                text("SELECT revoked_at FROM core.platform_grants WHERE id = :i"),
                {"i": seed.grant_id},
            ).scalar_one()
            is None
        )


@pytest.mark.parametrize(
    ("statement", "params"),
    [
        (
            "INSERT INTO core.platform_operators (id, user_id, status) VALUES (:id, :u, 'active')",
            "user",
        ),
        (
            "INSERT INTO core.platform_grants (id, operator_id, permission) "
            "VALUES (:id, :o, 'platform.tenant:read')",
            "operator",
        ),
        (
            "INSERT INTO core.platform_audit_log "
            "(id, actor_type, actor_user_id, action, target_type, outcome) "
            "VALUES (:id, 'user', :u, 'platform.test', 'operator', 'success')",
            "user",
        ),
    ],
)
def test_tenant_bound_transaction_cannot_insert_platform_rows(
    app: Engine, seed: Seed, statement: str, params: str
) -> None:
    values: dict[str, object] = {"id": uuid.uuid4()}
    if params == "user":
        values["u"] = seed.user() if "platform_operators" in statement else seed.user_id
    else:
        values["o"] = seed.operator_id
    with app.connect() as conn, conn.begin():
        conn.execute(text(_SET_TENANT), {"v": str(uuid.uuid4())})
        with pytest.raises(ProgrammingError) as excinfo:
            conn.execute(text(statement), values)
        assert "row-level security" in str(excinfo.value)


def test_malformed_tenant_context_hides_platform_rows_without_raising(
    app: Engine, seed: Seed
) -> None:
    """Fail closed, and without an error: the exclusion policy never casts.
    (A tenant-owned table would raise on the same value.)"""
    with app.connect() as conn, conn.begin() as tx:
        conn.execute(text(_SET_TENANT), {"v": "not-a-uuid"})
        assert _counts(conn, seed) == (0, 0, 0)
        tx.rollback()


def test_cleared_tenant_context_sees_platform_rows_again(app: Engine, seed: Seed) -> None:
    """The stated limit of the policy: the variable is not a credential.
    Code that clears it, or never sets it, sees the rows. This is why the
    policy is defence in depth and Core authorization is mandatory."""
    with app.connect() as conn, conn.begin() as tx:
        conn.execute(text(_SET_TENANT), {"v": str(uuid.uuid4())})
        assert _counts(conn, seed) == (0, 0, 0)
        conn.execute(text(_SET_TENANT), {"v": ""})
        assert _counts(conn, seed) == (1, 1, 1)
        tx.rollback()


def test_share_lock_taken_before_a_tenant_scope_is_still_held_after_it(
    admin: Engine, app: Engine, seed: Seed
) -> None:
    """ADR-0045 section 9c: a decision's `FOR SHARE` locks are taken before
    the first tenant scope is bound and must hold to the end of the
    transaction, whatever the variable is set to in between."""
    with app.connect() as holder, holder.begin() as tx:
        holder.execute(
            text("SELECT id FROM core.platform_operators WHERE id = :i FOR SHARE"),
            {"i": seed.operator_id},
        )
        holder.execute(text(_SET_TENANT), {"v": str(uuid.uuid4())})
        assert _counts(holder, seed) == (0, 0, 0)
        holder.execute(text(_SET_TENANT), {"v": ""})
        with admin.connect() as other, other.begin() as other_tx:
            other.execute(text("SET LOCAL lock_timeout = '300ms'"))
            with pytest.raises(DBAPIError) as excinfo:
                other.execute(
                    text("UPDATE core.platform_operators SET status = 'suspended' WHERE id = :i"),
                    {"i": seed.operator_id},
                )
            assert "lock timeout" in str(excinfo.value)
            other_tx.rollback()
        tx.rollback()


# --- constraints -------------------------------------------------------------


def test_one_live_operator_per_user_and_a_revoked_row_frees_the_user(
    admin: Engine, seed: Seed
) -> None:
    with admin.connect() as conn, conn.begin() as tx:
        with pytest.raises(IntegrityError), conn.begin_nested():
            conn.execute(
                text(
                    "INSERT INTO core.platform_operators (id, user_id, status) "
                    "VALUES (:id, :u, 'suspended')"
                ),
                {"id": uuid.uuid4(), "u": seed.user_id},
            )
        conn.execute(
            text("UPDATE core.platform_operators SET status = 'revoked' WHERE id = :i"),
            {"i": seed.operator_id},
        )
        conn.execute(
            text(
                "INSERT INTO core.platform_operators (id, user_id, status) "
                "VALUES (:id, :u, 'active')"
            ),
            {"id": uuid.uuid4(), "u": seed.user_id},
        )
        tx.rollback()


def test_one_live_grant_per_operator_and_permission_and_regrant_keeps_history(
    admin: Engine, seed: Seed
) -> None:
    insert = text(
        "INSERT INTO core.platform_grants (id, operator_id, permission) "
        "VALUES (:id, :o, 'platform.authority:manage')"
    )
    with admin.connect() as conn, conn.begin() as tx:
        with pytest.raises(IntegrityError), conn.begin_nested():
            conn.execute(insert, {"id": uuid.uuid4(), "o": seed.operator_id})
        conn.execute(
            text("UPDATE core.platform_grants SET revoked_at = now() WHERE id = :i"),
            {"i": seed.grant_id},
        )
        conn.execute(insert, {"id": uuid.uuid4(), "o": seed.operator_id})
        rows = conn.execute(
            text(
                "SELECT count(*), count(revoked_at) FROM core.platform_grants "
                "WHERE operator_id = :o AND permission = 'platform.authority:manage'"
            ),
            {"o": seed.operator_id},
        ).one()
        assert tuple(rows) == (2, 1)
        tx.rollback()


@pytest.mark.parametrize(
    "statement",
    [
        # A permission outside the closed vocabulary.
        "INSERT INTO core.platform_grants (id, operator_id, permission) "
        "VALUES (:id, :o, 'platform.tenant:purge')",
        # A tenant permission is not a platform permission.
        "INSERT INTO core.platform_grants (id, operator_id, permission) "
        "VALUES (:id, :o, 'membership_role:create')",
        # An operator status outside the vocabulary.
        "INSERT INTO core.platform_operators (id, user_id, status) VALUES (:id, :u2, 'owner')",
        # A user actor without a user id.
        "INSERT INTO core.platform_audit_log (id, actor_type, action, target_type, outcome) "
        "VALUES (:id, 'user', 'x', 'y', 'success')",
        # A system actor without a purpose.
        "INSERT INTO core.platform_audit_log (id, actor_type, action, target_type, outcome) "
        "VALUES (:id, 'system', 'x', 'y', 'success')",
        # A person recorded as system: a user id on a system row.
        "INSERT INTO core.platform_audit_log "
        "(id, actor_type, actor_user_id, system_authority, action, target_type, outcome) "
        "VALUES (:id, 'system', :u, 'platform_bootstrap', 'x', 'y', 'success')",
        # An actor type the platform audit does not have.
        "INSERT INTO core.platform_audit_log "
        "(id, actor_type, action, target_type, outcome) "
        "VALUES (:id, 'service_account', 'x', 'y', 'success')",
        # An outcome outside the vocabulary.
        "INSERT INTO core.platform_audit_log "
        "(id, actor_type, actor_user_id, action, target_type, outcome) "
        "VALUES (:id, 'user', :u, 'x', 'y', 'ok')",
    ],
)
def test_check_constraints_reject_invalid_rows(admin: Engine, seed: Seed, statement: str) -> None:
    values = {
        "id": uuid.uuid4(),
        "o": seed.operator_id,
        "u": seed.user_id,
        "u2": seed.user() if ":u2" in statement else None,
    }
    params = {key: value for key, value in values.items() if f":{key}" in statement}
    with admin.connect() as conn, conn.begin() as tx:
        with pytest.raises(IntegrityError) as excinfo:
            conn.execute(text(statement), params)
        assert "violates check constraint" in str(excinfo.value)
        tx.rollback()


def test_platform_audit_metadata_is_size_bounded_in_the_database(admin: Engine, seed: Seed) -> None:
    with admin.connect() as conn, conn.begin() as tx:
        with pytest.raises(IntegrityError) as excinfo:
            conn.execute(
                text(
                    "INSERT INTO core.platform_audit_log "
                    "(id, actor_type, actor_user_id, action, target_type, outcome, metadata) "
                    "VALUES (:id, 'user', :u, 'x', 'y', 'success', CAST(:m AS json))"
                ),
                {"id": uuid.uuid4(), "u": seed.user_id, "m": '{"k": "' + "x" * 9000 + '"}'},
            )
        assert "ck_platform_audit_log_metadata_size" in str(excinfo.value)
        tx.rollback()
