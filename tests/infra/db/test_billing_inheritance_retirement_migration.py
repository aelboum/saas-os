"""Migration test for `aa43b942bf93` (Phase 5.3 step 5 -- `inherits_billing`
retired forward) against real disposable PostgreSQL.

Verifies that an existing `true` survives the upgrade untouched, that after
it no new `true` can be written (insert or false -> true), that `true ->
false` stays possible, and that the downgrade removes only the rule.

**Destructive** (downgrades past `aa43b942bf93`); disposable databases
only. Marked `integration`.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from infra.db.config import get_migrations_database_config
from infra.db.engine import build_engine
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parents[3]
_REVISION = "aa43b942bf93"  # pragma: allowlist secret
_PREVIOUS = "732590273bc1"  # pragma: allowlist secret


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


def _admin(sql: str, **params: object) -> list:  # type: ignore[type-arg]
    engine = build_engine(get_migrations_database_config())
    try:
        with engine.begin() as conn:
            result = conn.execute(text(sql), params)
            return list(result.all()) if result.returns_rows else []
    finally:
        engine.dispose()


def _inherits(tenant: uuid.UUID) -> bool:
    return bool(
        _admin("SELECT inherits_billing FROM core.tenants WHERE id = :t", t=str(tenant))[0][0]
    )


def test_the_retirement_rule_keeps_existing_rows_and_refuses_new_ones() -> None:
    legacy, flat = uuid.uuid4(), uuid.uuid4()
    try:
        command.downgrade(_cfg(), _PREVIOUS)
        _admin(
            "INSERT INTO core.tenants (id, name, status, inherits_billing) "
            "VALUES (:l, 'legacy', 'active', true), (:f, 'flat', 'active', false)",
            l=str(legacy),
            f=str(flat),
        )

        command.upgrade(_cfg(), _REVISION)
        assert _inherits(legacy) is True  # nothing converted
        for sql in (
            "UPDATE core.tenants SET inherits_billing = true WHERE id = :t",
            "INSERT INTO core.tenants (id, name, status, inherits_billing) "
            "VALUES (gen_random_uuid(), 'new', 'active', true)",
        ):
            with pytest.raises(DBAPIError, match="retired"):
                _admin(sql, t=str(flat))
        _admin("UPDATE core.tenants SET status = 'suspended' WHERE id = :t", t=str(legacy))
        _admin("UPDATE core.tenants SET inherits_billing = false WHERE id = :t", t=str(legacy))
        assert _inherits(legacy) is False

        command.downgrade(_cfg(), _PREVIOUS)
        _admin("UPDATE core.tenants SET inherits_billing = true WHERE id = :t", t=str(flat))
        assert _inherits(flat) is True  # the rule is gone; nothing else changed
    finally:
        command.upgrade(_cfg(), "head")
        _admin(
            "DELETE FROM core.tenant_ancestry WHERE tenant_id = ANY(:t) OR ancestor_id = ANY(:t)",
            t=[str(legacy), str(flat)],
        )
        _admin("DELETE FROM core.tenants WHERE id = ANY(:t)", t=[str(legacy), str(flat)])
