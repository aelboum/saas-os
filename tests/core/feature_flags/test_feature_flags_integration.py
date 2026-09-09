"""Feature-flag lifecycle integration tests against a real PostgreSQL
instance with the Phase 4.2 tables actually migrated
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.2).

Marked `integration` and excluded from the default `pytest` run.

How to run this test locally:

    docker compose up -d db
    alembic upgrade head
    DATABASE_URL=postgresql+psycopg://saas_os_app:changeme_app@localhost:5432/saas_os \\
        MIGRATIONS_DATABASE_URL=postgresql+psycopg://saas_os:changeme@localhost:5432/saas_os \\
        pytest -m integration tests/core/feature_flags/test_feature_flags_integration.py
"""

from __future__ import annotations

import uuid

import pytest
from core.audit_log.service import list as list_audit_entries
from core.feature_flags.errors import DuplicateFeatureFlagKeyError, FeatureFlagNotFoundError
from core.feature_flags.service import (
    create_flag,
    evaluate_flag,
    get_flag,
    get_tenant_override,
    list_flags,
    remove_tenant_override,
    set_tenant_override,
)
from core.identity.service import create_user
from infra.db.config import get_database_config, get_migrations_database_config
from infra.db.engine import build_engine, get_engine
from infra.db.session import build_session_factory, session_scope, tenant_session_scope
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from core.tenancy import create_tenant

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_reachable_database_with_feature_flags_tables() -> None:
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
            conn.execute(text("SELECT 1 FROM core.feature_flag_tenant_overrides LIMIT 1"))
    except OperationalError as exc:
        pytest.skip(
            f"PostgreSQL not reachable at the configured DATABASE_URL "
            f"({config.url.split('@')[-1]}): {exc}. Run `docker compose up -d db` first "
            "-- see this file's module docstring."
        )
    except ProgrammingError as exc:
        pytest.skip(
            f"core.feature_flag_tenant_overrides does not exist yet -- "
            f"run `alembic upgrade head` first: {exc}"
        )
    finally:
        probe_engine.dispose()

    try:
        get_migrations_database_config()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"MIGRATIONS_DATABASE_URL not configured for the integration test: {exc}")


def _admin_delete_audit_log_for_tenant(tenant_id: uuid.UUID) -> None:
    # core.audit_log DELETE is REVOKEd from the restricted runtime role
    # entirely (docs/IMPLEMENTATION-ROADMAP.md Phase 3.4) -- test cleanup
    # must use the privileged migrations role here.
    engine = build_engine(get_migrations_database_config())
    try:
        factory = build_session_factory(engine)
        with session_scope(session_factory=factory) as session:
            session.execute(
                text("DELETE FROM core.audit_log WHERE tenant_id = :t"), {"t": str(tenant_id)}
            )
    finally:
        engine.dispose()


def _unique_key(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class _Fixture:
    def __init__(self) -> None:
        self.tenant = create_tenant(f"ff-tenant-{uuid.uuid4().hex[:8]}")
        self.user = create_user()
        self.key = _unique_key("flag")

    def cleanup(self) -> None:
        with tenant_session_scope(self.tenant.id) as session:
            session.execute(
                text("DELETE FROM core.feature_flag_tenant_overrides WHERE tenant_id = :t"),
                {"t": str(self.tenant.id)},
            )
        _admin_delete_audit_log_for_tenant(self.tenant.id)
        with session_scope() as session:
            session.execute(text("DELETE FROM core.feature_flags WHERE key = :k"), {"k": self.key})
            session.execute(
                text("DELETE FROM core.users WHERE id = :id"), {"id": str(self.user.id)}
            )
            session.execute(
                text("DELETE FROM core.tenants WHERE id = :id"), {"id": str(self.tenant.id)}
            )


@pytest.fixture
def fx():
    fixture = _Fixture()
    yield fixture
    fixture.cleanup()


# --- Flag definitions -------------------------------------------------------


def test_create_and_get_flag(fx: _Fixture) -> None:
    flag = create_flag(fx.key, enabled_by_default=True)
    assert flag.key == fx.key
    assert flag.enabled_by_default is True

    fetched = get_flag(fx.key)
    assert fetched.id == flag.id


def test_create_flag_defaults_to_disabled(fx: _Fixture) -> None:
    flag = create_flag(fx.key)
    assert flag.enabled_by_default is False


def test_duplicate_flag_key_rejected(fx: _Fixture) -> None:
    create_flag(fx.key)
    with pytest.raises(DuplicateFeatureFlagKeyError):
        create_flag(fx.key)


def test_get_unknown_flag_raises(fx: _Fixture) -> None:
    with pytest.raises(FeatureFlagNotFoundError):
        get_flag(_unique_key("nonexistent"))


def test_list_flags_includes_created_flag(fx: _Fixture) -> None:
    create_flag(fx.key)
    keys = {f.key for f in list_flags()}
    assert fx.key in keys


def test_create_flag_does_not_write_an_audit_entry(fx: _Fixture) -> None:
    """A flag definition is global, not tenant-owned data -- there is no
    tenant_id to attribute an audit record to (mirrors core/rbac's
    register_permission(), which also does not audit-log)."""
    create_flag(fx.key)
    entries = list_audit_entries(fx.tenant.id)
    assert all(e.resource_id != fx.key for e in entries)


# --- Targeting: per-tenant overrides -----------------------------------


def test_evaluate_flag_uses_global_default_with_no_override(fx: _Fixture) -> None:
    create_flag(fx.key, enabled_by_default=True)
    assert evaluate_flag(fx.tenant.id, fx.key) is True


def test_set_tenant_override_wins_over_global_default(fx: _Fixture) -> None:
    create_flag(fx.key, enabled_by_default=False)
    set_tenant_override(fx.tenant.id, fx.key, True)
    assert evaluate_flag(fx.tenant.id, fx.key) is True


def test_set_tenant_override_can_disable_a_default_enabled_flag(fx: _Fixture) -> None:
    create_flag(fx.key, enabled_by_default=True)
    set_tenant_override(fx.tenant.id, fx.key, False)
    assert evaluate_flag(fx.tenant.id, fx.key) is False


def test_set_tenant_override_twice_updates_in_place_not_duplicate(fx: _Fixture) -> None:
    create_flag(fx.key, enabled_by_default=False)
    set_tenant_override(fx.tenant.id, fx.key, True)
    set_tenant_override(fx.tenant.id, fx.key, False)

    with tenant_session_scope(fx.tenant.id) as session:
        rows = session.execute(
            text("SELECT enabled FROM core.feature_flag_tenant_overrides WHERE tenant_id = :t"),
            {"t": str(fx.tenant.id)},
        ).all()
    assert len(rows) == 1
    assert rows[0].enabled is False


def test_get_tenant_override_reflects_current_state(fx: _Fixture) -> None:
    create_flag(fx.key)
    assert get_tenant_override(fx.tenant.id, fx.key) is None

    set_tenant_override(fx.tenant.id, fx.key, True)
    override = get_tenant_override(fx.tenant.id, fx.key)
    assert override is not None
    assert override.enabled is True


def test_remove_tenant_override_reverts_to_global_default(fx: _Fixture) -> None:
    create_flag(fx.key, enabled_by_default=False)
    set_tenant_override(fx.tenant.id, fx.key, True)
    assert evaluate_flag(fx.tenant.id, fx.key) is True

    remove_tenant_override(fx.tenant.id, fx.key)
    assert evaluate_flag(fx.tenant.id, fx.key) is False
    assert get_tenant_override(fx.tenant.id, fx.key) is None


def test_remove_tenant_override_is_idempotent(fx: _Fixture) -> None:
    create_flag(fx.key)
    remove_tenant_override(fx.tenant.id, fx.key)  # no-op, no error
    remove_tenant_override(fx.tenant.id, fx.key)  # still no-op


def test_set_tenant_override_on_unknown_flag_raises(fx: _Fixture) -> None:
    with pytest.raises(FeatureFlagNotFoundError):
        set_tenant_override(fx.tenant.id, _unique_key("nonexistent"), True)


# --- Evaluation SDK safe-default behavior --------------------------------


def test_evaluate_unknown_flag_returns_caller_supplied_default(fx: _Fixture) -> None:
    assert evaluate_flag(fx.tenant.id, _unique_key("nonexistent"), default=True) is True
    assert evaluate_flag(fx.tenant.id, _unique_key("nonexistent"), default=False) is False


def test_evaluate_flag_a_flag_flip_is_observed_without_redeploy(fx: _Fixture) -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 4.2's own Tests requirement:
    "a flag flip is observed by a consuming test client without redeploy"
    -- the same evaluate_flag() call, called twice, reflects the override
    change made in between with no process restart."""
    create_flag(fx.key, enabled_by_default=False)
    assert evaluate_flag(fx.tenant.id, fx.key) is False

    set_tenant_override(fx.tenant.id, fx.key, True)
    assert evaluate_flag(fx.tenant.id, fx.key) is True

    set_tenant_override(fx.tenant.id, fx.key, False)
    assert evaluate_flag(fx.tenant.id, fx.key) is False


# --- Audit logging -----------------------------------------------------


def test_set_tenant_override_writes_an_audit_entry(fx: _Fixture) -> None:
    create_flag(fx.key)
    set_tenant_override(fx.tenant.id, fx.key, True, actor_user_id=fx.user.id)

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "feature_flag.override_set"]
    assert len(matching) == 1
    entry = matching[0]
    assert entry.tenant_id == fx.tenant.id
    assert entry.actor_user_id == fx.user.id
    assert entry.resource_type == "feature_flag"
    assert entry.resource_id == fx.key
    assert entry.outcome == "success"
    assert entry.entry_metadata == {"enabled": True}


def test_set_tenant_override_without_actor_is_audited_as_system(fx: _Fixture) -> None:
    create_flag(fx.key)
    set_tenant_override(fx.tenant.id, fx.key, True)

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "feature_flag.override_set"]
    assert len(matching) == 1
    assert matching[0].actor_type == "system"
    assert matching[0].actor_user_id is None


def test_remove_tenant_override_writes_an_audit_entry(fx: _Fixture) -> None:
    create_flag(fx.key)
    set_tenant_override(fx.tenant.id, fx.key, True)
    remove_tenant_override(fx.tenant.id, fx.key, actor_user_id=fx.user.id)

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "feature_flag.override_removed"]
    assert len(matching) == 1
    assert matching[0].resource_id == fx.key


def test_remove_tenant_override_no_op_does_not_write_an_audit_entry(fx: _Fixture) -> None:
    create_flag(fx.key)
    remove_tenant_override(fx.tenant.id, fx.key)  # nothing to remove

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "feature_flag.override_removed"]
    assert matching == []


def test_audit_entries_never_carry_the_flag_default_only_the_targeting_value(
    fx: _Fixture,
) -> None:
    """The audit metadata records the tenant's *targeting* decision
    (`enabled`), never anything resembling a secret -- there is no secret
    in this module at all, but this test documents the metadata shape
    stays minimal and intentional."""
    create_flag(fx.key)
    set_tenant_override(fx.tenant.id, fx.key, True)

    entries = list_audit_entries(fx.tenant.id)
    matching = [e for e in entries if e.action == "feature_flag.override_set"]
    metadata = matching[0].entry_metadata
    assert metadata is not None
    assert set(metadata.keys()) == {"enabled"}
