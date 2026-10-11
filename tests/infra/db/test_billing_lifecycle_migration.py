"""Migration test for `41e8273a685d` (Billing Foundation v2 Phase 3 --
lifecycle safety) against real disposable PostgreSQL, with representative
pre-Phase-3 data: a legacy `active` row, a legacy `canceled` row, and a
Phase 2 commercial row (billing account recorded, `active` never
provider-confirmed).

Verifies that the upgrade rewrites no status and invents nothing, marks
every pre-existing row `legacy_unverified`, backfills a merchant only from
an already-recorded billing account, refuses -- without changing anything
-- to run while duplicate live subscriptions exist, and reverses cleanly.

**Destructive** (downgrades past `41e8273a685d`); disposable databases
only. Marked `integration`, mirroring
`tests/infra/db/test_billing_commercial_parties_migration.py`.
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
    finally:
        engine.dispose()


pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "41e8273a685d"  # pragma: allowlist secret
_PREVIOUS = "6e99825a629c"  # pragma: allowlist secret
_NEW_COLUMNS = {"verification", "merchant_account_id"}


@pytest.fixture(autouse=True)
def _require_reachable_privileged_database() -> None:
    get_migrations_database_config.cache_clear()
    try:
        config = get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")
    probe = build_engine(config, connect_args={"connect_timeout": 1})
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:
        pytest.skip(f"PostgreSQL not reachable at MIGRATIONS_DATABASE_URL: {exc}")
    finally:
        probe.dispose()


def _cfg() -> Config:
    return Config(str(_REPO_ROOT / "alembic.ini"))


def _admin(sql: str, params: dict[str, object] | None = None) -> list:
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(sql), params or {})
            return list(result.all()) if result.returns_rows else []
    finally:
        engine.dispose()


def _columns() -> set[str]:
    return {
        row[0]
        for row in _admin(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'core' "
            "AND table_name = 'billing_subscriptions'"
        )
    }


class _Seed:
    def __init__(self) -> None:
        self.legacy_tenant, self.canceled_tenant, self.commercial_tenant, self.platform = (
            uuid.uuid4() for _ in range(4)
        )
        self.plan, self.merchant, self.account = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        self.legacy_sub, self.canceled_sub, self.commercial_sub, self.duplicate_sub = (
            uuid.uuid4() for _ in range(4)
        )
        self.plan_key = f"p3-migration-{uuid.uuid4().hex[:8]}"

    def insert(self) -> None:
        for tenant in (
            self.legacy_tenant,
            self.canceled_tenant,
            self.commercial_tenant,
            self.platform,
        ):
            _admin(
                "INSERT INTO core.tenants (id, name, status) "
                "VALUES (:id, 'p3-migration', 'active')",
                {"id": str(tenant)},
            )
        _admin(
            "INSERT INTO core.billing_plans (id, key, name, entitlements) "
            "VALUES (:id, :k, 'Seed', '{}')",
            {"id": str(self.plan), "k": self.plan_key},
        )
        _admin(
            "INSERT INTO core.billing_merchant_accounts (id, tenant_id, provider, "
            "provider_account_ref, status) VALUES (:id, :t, 'fake', :ref, 'active')",
            {"id": str(self.merchant), "t": str(self.platform), "ref": f"acct-{self.merchant.hex}"},
        )
        _admin(
            "INSERT INTO core.billing_accounts (id, tenant_id, merchant_tenant_id, "
            "merchant_account_id, status) VALUES (:id, :t, :mt, :m, 'active')",
            {
                "id": str(self.account),
                "t": str(self.commercial_tenant),
                "mt": str(self.platform),
                "m": str(self.merchant),
            },
        )
        for sub, tenant, status in (
            (self.legacy_sub, self.legacy_tenant, "active"),
            (self.canceled_sub, self.canceled_tenant, "canceled"),
        ):
            _admin(
                "INSERT INTO core.billing_subscriptions (id, tenant_id, plan_id, status, "
                "provider_subscription_id) VALUES (:id, :t, :p, :s, :ref)",
                {
                    "id": str(sub),
                    "t": str(tenant),
                    "p": str(self.plan),
                    "s": status,
                    "ref": sub.hex,
                },
            )
        self.insert_commercial(self.commercial_sub)

    def insert_commercial(self, sub: uuid.UUID) -> None:
        _admin(
            "INSERT INTO core.billing_subscriptions (id, tenant_id, plan_id, status, "
            "provider_subscription_id, payer_tenant_id, billing_account_id, provider) "
            "VALUES (:id, :t, :p, 'active', :ref, :t, :a, 'fake')",
            {
                "id": str(sub),
                "t": str(self.commercial_tenant),
                "p": str(self.plan),
                "ref": sub.hex,
                "a": str(self.account),
            },
        )

    def delete(self) -> None:
        tenants = [
            str(t)
            for t in (
                self.legacy_tenant,
                self.canceled_tenant,
                self.commercial_tenant,
                self.platform,
            )
        ]
        _admin("DELETE FROM core.billing_subscriptions WHERE tenant_id = ANY(:t)", {"t": tenants})
        _admin("DELETE FROM core.billing_accounts WHERE tenant_id = ANY(:t)", {"t": tenants})
        _admin(
            "DELETE FROM core.billing_merchant_accounts WHERE tenant_id = ANY(:t)", {"t": tenants}
        )
        _admin("DELETE FROM core.billing_plans WHERE id = :id", {"id": str(self.plan)})
        _admin_clear_audit_references({"t": tenants}, table="tenants")
        _admin("DELETE FROM core.tenants WHERE id = ANY(:t)", {"t": tenants})


@pytest.fixture
def seeded():
    cfg = _cfg()
    command.upgrade(cfg, "head")
    command.downgrade(cfg, _PREVIOUS)
    seed = _Seed()
    seed.insert()
    try:
        yield seed
    finally:
        seed.delete()
        command.upgrade(cfg, "head")


def _rows(seed: _Seed) -> dict[uuid.UUID, tuple]:
    return {
        row[0]: tuple(row[1:])
        for row in _admin(
            "SELECT id, status, verification, merchant_account_id, billing_account_id "
            "FROM core.billing_subscriptions WHERE id = ANY(:ids)",
            {"ids": [str(seed.legacy_sub), str(seed.canceled_sub), str(seed.commercial_sub)]},
        )
    }


def test_upgrade_marks_existing_rows_legacy_and_invents_nothing(seeded: _Seed) -> None:
    assert not _columns() & _NEW_COLUMNS
    command.upgrade(_cfg(), _REVISION)

    rows = _rows(seeded)
    assert rows[seeded.legacy_sub] == ("active", "legacy_unverified", None, None)
    assert rows[seeded.canceled_sub] == ("canceled", "legacy_unverified", None, None)
    # The merchant is taken from the billing account the row already records.
    assert rows[seeded.commercial_sub] == (
        "active",
        "legacy_unverified",
        seeded.merchant,
        seeded.account,
    )


def test_upgrade_refuses_duplicate_live_subscriptions_and_changes_nothing(seeded: _Seed) -> None:
    seeded.insert_commercial(seeded.duplicate_sub)
    before = _admin("SELECT id, status FROM core.billing_subscriptions ORDER BY id")

    with pytest.raises(RuntimeError, match=r"1 \(tenant_id, merchant_account_id\) group"):
        command.upgrade(_cfg(), _REVISION)

    assert not _columns() & _NEW_COLUMNS
    assert _admin("SELECT id, status FROM core.billing_subscriptions ORDER BY id") == before

    # Explicit remediation (here: removing the test's own duplicate), then
    # the upgrade proceeds.
    _admin(
        "DELETE FROM core.billing_subscriptions WHERE id = :id", {"id": str(seeded.duplicate_sub)}
    )
    command.upgrade(_cfg(), _REVISION)
    assert _columns() >= _NEW_COLUMNS


def test_upgraded_schema_enforces_the_invariants_and_reverses_cleanly(seeded: _Seed) -> None:
    command.upgrade(_cfg(), _REVISION)

    with pytest.raises(IntegrityError, match="uq_billing_subscriptions_one_live_per_merchant"):
        _admin(
            "INSERT INTO core.billing_subscriptions (id, tenant_id, plan_id, status, "
            "provider_subscription_id, payer_tenant_id, billing_account_id, provider, "
            "merchant_account_id) VALUES (:id, :t, :p, 'pending', 'dup', :t, :a, 'fake', :m)",
            {
                "id": str(seeded.duplicate_sub),
                "t": str(seeded.commercial_tenant),
                "p": str(seeded.plan),
                "a": str(seeded.account),
                "m": str(seeded.merchant),
            },
        )
    # A Phase-2-shaped commercial insert (no merchant) is no longer accepted.
    with pytest.raises(IntegrityError, match="ck_billing_subscriptions_merchant_pair"):
        seeded.insert_commercial(seeded.duplicate_sub)
    with pytest.raises(IntegrityError, match="ck_billing_subscriptions_verified_is_commercial"):
        _admin(
            "UPDATE core.billing_subscriptions SET verification = 'verified' WHERE id = :id",
            {"id": str(seeded.legacy_sub)},
        )
    with pytest.raises(IntegrityError, match="fk_billing_subscriptions_billing_account_merchant"):
        _admin(
            "UPDATE core.billing_subscriptions SET merchant_account_id = :m WHERE id = :id",
            {"m": str(uuid.uuid4()), "id": str(seeded.commercial_sub)},
        )

    command.downgrade(_cfg(), _PREVIOUS)
    assert not _columns() & _NEW_COLUMNS
    assert (
        len(
            _admin(
                "SELECT id FROM core.billing_subscriptions WHERE id = ANY(:ids)",
                {
                    "ids": [
                        str(seeded.legacy_sub),
                        str(seeded.canceled_sub),
                        str(seeded.commercial_sub),
                    ]
                },
            )
        )
        == 3
    )
