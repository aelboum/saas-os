"""Migration test for `d23cbb2ba746` (Phase 5.3 step 2 -- Catalog v2)
against real disposable PostgreSQL, with a representative pre-Catalog-v2
plan.

Verifies that the upgrade invents no owner (an existing plan stays legacy,
unowned, public and active), keeps legacy keys unique while letting owned
plans share a key across owners, refuses to downgrade -- changing nothing --
while an owned plan exists, and reverses cleanly otherwise.

**Destructive** (downgrades past `d23cbb2ba746`); disposable databases
only. Marked `integration`, mirroring
`tests/infra/db/test_billing_lifecycle_migration.py`.
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

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "d23cbb2ba746"  # pragma: allowlist secret
_PREVIOUS = "e5b19c7d3a60"  # pragma: allowlist secret


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


def _admin(sql: str, params: dict[str, object] | None = None) -> list:  # type: ignore[type-arg]
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(sql), params or {})
            return list(result.all()) if result.returns_rows else []
    finally:
        engine.dispose()


def _plan_columns() -> set[str]:
    return {
        row[0]
        for row in _admin(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'core' "
            "AND table_name = 'billing_plans'"
        )
    }


def _offers_table_exists() -> bool:
    return bool(_admin("SELECT to_regclass('core.billing_plan_offers') IS NOT NULL")[0][0])


def test_catalog_v2_upgrade_invents_nothing_and_reverses_cleanly() -> None:
    legacy_plan, legacy_key = uuid.uuid4(), f"c2-legacy-{uuid.uuid4().hex[:8]}"
    owners = [uuid.uuid4(), uuid.uuid4()]
    merchants = [uuid.uuid4(), uuid.uuid4()]
    owned_plans = [uuid.uuid4(), uuid.uuid4()]
    shared_key = f"c2-shared-{uuid.uuid4().hex[:8]}"
    try:
        command.downgrade(_cfg(), _PREVIOUS)
        assert "owner_tenant_id" not in _plan_columns()
        assert not _offers_table_exists()
        _admin(
            "INSERT INTO core.billing_plans (id, key, name, entitlements) "
            "VALUES (:id, :k, 'Legacy', '{}')",
            {"id": str(legacy_plan), "k": legacy_key},
        )

        command.upgrade(_cfg(), _REVISION)
        [row] = _admin(
            "SELECT owner_tenant_id, merchant_account_id, visibility, status, legacy "
            "FROM core.billing_plans WHERE id = :id",
            {"id": str(legacy_plan)},
        )
        assert tuple(row) == (None, None, "public", "active", True)  # nothing guessed
        with pytest.raises(IntegrityError):
            _admin(
                "INSERT INTO core.billing_plans (id, key, name, entitlements) "
                "VALUES (:id, :k, 'Twin', '{}')",
                {"id": str(uuid.uuid4()), "k": legacy_key},
            )
        with pytest.raises(IntegrityError):  # a non-legacy plan must have an owner
            _admin(
                "INSERT INTO core.billing_plans (id, key, name, entitlements, legacy) "
                "VALUES (:id, :k, 'Orphan', '{}', false)",
                {"id": str(uuid.uuid4()), "k": shared_key},
            )
        for owner, merchant, plan in zip(owners, merchants, owned_plans, strict=True):
            _admin(
                "INSERT INTO core.tenants (id, name, status) VALUES (:id, 'c2', 'active')",
                {"id": str(owner)},
            )
            _admin(
                "INSERT INTO core.billing_merchant_accounts "
                "(id, tenant_id, provider, provider_account_ref, status) "
                "VALUES (:id, :t, 'fake', :ref, 'active')",
                {"id": str(merchant), "t": str(owner), "ref": f"acct-{uuid.uuid4().hex}"},
            )
            _admin(
                "INSERT INTO core.billing_plans (id, key, name, entitlements, owner_tenant_id, "
                "merchant_account_id, legacy) VALUES (:id, :k, 'Owned', '{}', :o, :m, false)",
                {"id": str(plan), "k": shared_key, "o": str(owner), "m": str(merchant)},
            )

        with pytest.raises(RuntimeError, match="Refusing to downgrade Catalog v2"):
            command.downgrade(_cfg(), _PREVIOUS)
        assert "owner_tenant_id" in _plan_columns() and _offers_table_exists()

        _admin("DELETE FROM core.billing_plans WHERE id = ANY(:ids)", {"ids": owned_plans})
        command.downgrade(_cfg(), _PREVIOUS)
        assert "owner_tenant_id" not in _plan_columns()
        with pytest.raises(IntegrityError):  # UNIQUE (key) restored
            _admin(
                "INSERT INTO core.billing_plans (id, key, name, entitlements) "
                "VALUES (:id, :k, 'Twin', '{}')",
                {"id": str(uuid.uuid4()), "k": legacy_key},
            )
    finally:
        command.upgrade(_cfg(), "head")
        _admin("DELETE FROM core.billing_plans WHERE id = ANY(:ids)", {"ids": owned_plans})
        _admin("DELETE FROM core.billing_plans WHERE key = :k", {"k": legacy_key})
        _admin(
            "DELETE FROM core.billing_merchant_accounts WHERE id = ANY(:ids)", {"ids": merchants}
        )
        _admin("DELETE FROM core.tenants WHERE id = ANY(:ids)", {"ids": owners})
