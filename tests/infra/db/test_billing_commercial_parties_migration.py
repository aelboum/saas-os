"""Migration test for `6e99825a629c` (Billing Foundation v2 Phase 2,
docs/ADR/0029-commercial-parties-and-billing-relationships.md) against
real disposable PostgreSQL: upgrading a database that already holds
pre-Phase-2 subscriptions preserves every row unchanged, fabricates no
payer, billing account, provider or provider customer, and the migration
reverses cleanly at the schema level.

**Destructive**: downgrades past, then re-applies, `6e99825a629c` on
whatever database `MIGRATIONS_DATABASE_URL` points at -- it drops the
three commercial-party tables and the three new subscription columns
(and any data in them). Run only against a disposable database. Marked
`integration` and excluded from the default `pytest` run, mirroring
`tests/infra/db/test_billing_migration_rollback.py`.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/infra/db/test_billing_commercial_parties_migration.py
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError

from saas_os.infra.db.config import get_migrations_database_config
from saas_os.infra.db.engine import build_engine


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
            # ADR-0045 Phase C: lifecycle changes also write platform audit
            # rows, which reference the tenant or the acting user and which
            # the runtime role can never delete.
            platform_where = (
                "target_tenant_id::text = ANY(:v)"
                if table == "tenants"
                else "actor_user_id::text = ANY(:v)"
            )
            # A migration test may be cleaning up below the revision that
            # creates the table.
            if session.execute(text("SELECT to_regclass('core.platform_audit_log')")).scalar():
                session.execute(
                    text(f"DELETE FROM core.platform_audit_log WHERE {platform_where}"),  # noqa: S608
                    {"v": values},
                )
    finally:
        engine.dispose()


pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "6e99825a629c"
_PREVIOUS = "76a55dfb1782"  # pragma: allowlist secret -- an alembic revision id, not a secret
_NEW_TABLES = ("billing_merchant_accounts", "billing_accounts", "billing_provider_refs")
_NEW_SUBSCRIPTION_COLUMNS = {"payer_tenant_id", "billing_account_id", "provider"}


@pytest.fixture(autouse=True)
def _require_reachable_privileged_database() -> None:
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")
    probe_engine = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable at MIGRATIONS_DATABASE_URL: {exc}")
    finally:
        probe_engine.dispose()


def _alembic_config() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _admin(sql: str, params: dict[str, object] | None = None) -> list:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(sql), params or {})
            return list(result.all()) if result.returns_rows else []
    finally:
        engine.dispose()


def _tables() -> set[str]:
    rows = _admin(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'core' "
        "AND table_name = ANY(:t)",
        {"t": list(_NEW_TABLES)},
    )
    return {row[0] for row in rows}


def _subscription_columns() -> set[str]:
    rows = _admin(
        "SELECT column_name FROM information_schema.columns WHERE table_schema = 'core' "
        "AND table_name = 'billing_subscriptions'"
    )
    return {row[0] for row in rows}


def test_upgrade_preserves_existing_subscriptions_and_fabricates_nothing() -> None:
    cfg = _alembic_config()
    command.upgrade(cfg, "head")
    command.downgrade(cfg, _PREVIOUS)
    assert _tables() == set()
    assert not _subscription_columns() & _NEW_SUBSCRIPTION_COLUMNS

    tenant_id, plan_id, subscription_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    plan_key = f"pre-phase-2-{uuid.uuid4().hex[:8]}"
    try:
        # A pre-Phase-2 subscription, exactly as the old schema stored it.
        _admin(
            "INSERT INTO core.tenants (id, name, status) VALUES (:id, 'pre-phase-2', 'active')",
            {"id": str(tenant_id)},
        )
        _admin(
            "INSERT INTO core.billing_plans (id, key, name, entitlements) "
            "VALUES (:id, :k, 'Legacy', '{\"seats\": 2}')",
            {"id": str(plan_id), "k": plan_key},
        )
        _admin(
            "INSERT INTO core.billing_subscriptions (id, tenant_id, plan_id, status, "
            "provider_subscription_id) VALUES (:id, :t, :p, 'active', 'sub_legacy123')",
            {"id": str(subscription_id), "t": str(tenant_id), "p": str(plan_id)},
        )
        before = _admin(
            "SELECT tenant_id, plan_id, status, provider_subscription_id, created_at, updated_at "
            "FROM core.billing_subscriptions WHERE id = :id",
            {"id": str(subscription_id)},
        )

        command.upgrade(cfg, _REVISION)

        assert _tables() == set(_NEW_TABLES)
        assert _subscription_columns() >= _NEW_SUBSCRIPTION_COLUMNS
        after = _admin(
            "SELECT tenant_id, plan_id, status, provider_subscription_id, created_at, updated_at, "
            "payer_tenant_id, billing_account_id, provider "
            "FROM core.billing_subscriptions WHERE id = :id",
            {"id": str(subscription_id)},
        )
        assert len(after) == 1
        # Unchanged, including `status = 'active'` (legacy-unverified, not
        # reconciled here) ...
        assert tuple(after[0][:6]) == tuple(before[0])
        # ... and no payer, billing account or provider is invented -- not
        # even from the shape of the provider id.
        assert after[0][6:] == (None, None, None)
        # Nothing was created in the new tables for it.
        for table in _NEW_TABLES:
            assert (
                _admin(
                    f"SELECT count(*) FROM core.{table} WHERE tenant_id = :t", {"t": str(tenant_id)}
                )[0][0]
                == 0
            )

        # The both-or-neither payer constraint is live.
        with pytest.raises(IntegrityError):
            _admin(
                "UPDATE core.billing_subscriptions SET payer_tenant_id = tenant_id WHERE id = :id",
                {"id": str(subscription_id)},
            )

        # Reversible at the schema level, row still preserved.
        command.downgrade(cfg, _PREVIOUS)
        assert _tables() == set()
        assert not _subscription_columns() & _NEW_SUBSCRIPTION_COLUMNS
        assert (
            _admin(
                "SELECT count(*) FROM core.billing_subscriptions WHERE id = :id",
                {"id": str(subscription_id)},
            )[0][0]
            == 1
        )
    finally:
        command.upgrade(cfg, "head")
        _admin(
            "DELETE FROM core.billing_subscriptions WHERE id = :id", {"id": str(subscription_id)}
        )
        _admin("DELETE FROM core.billing_plans WHERE id = :id", {"id": str(plan_id)})
        _admin("DELETE FROM core.tenant_ancestry WHERE tenant_id = :t", {"t": str(tenant_id)})
        _admin_clear_audit_references({"id": str(tenant_id)}, table="tenants")
        _admin("DELETE FROM core.tenants WHERE id = :id", {"id": str(tenant_id)})


def test_fresh_head_schema_has_rls_on_owned_tables_and_none_on_the_global_index() -> None:
    command.upgrade(_alembic_config(), "head")
    rows = _admin(
        "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = ANY(:t)",
        {"t": [*_NEW_TABLES, "billing_subscriptions"]},
    )
    assert {row[0]: (row[1], row[2]) for row in rows} == {
        "billing_merchant_accounts": (True, True),
        "billing_accounts": (True, True),
        "billing_subscriptions": (True, True),
        "billing_provider_refs": (False, False),
    }
    constraints = {
        row[0]
        for row in _admin(
            "SELECT conname FROM pg_constraint WHERE conrelid IN ("
            "'core.billing_merchant_accounts'::regclass, 'core.billing_accounts'::regclass, "
            "'core.billing_provider_refs'::regclass, 'core.billing_subscriptions'::regclass)"
        )
    }
    assert {
        "uq_billing_merchant_accounts_provider_account",
        "uq_billing_merchant_accounts_tenant_id_id",
        "uq_billing_accounts_tenant_merchant",
        "uq_billing_accounts_tenant_id_id",
        "fk_billing_accounts_merchant_account",
        "uq_billing_provider_refs_provider_object",
        "ck_billing_subscriptions_payer_pair",
        "fk_billing_subscriptions_billing_account",
    } <= constraints
