"""`infra.db` public-surface guard (PRIV-03 Phase P6, privacy re-audit
finding RA-01) -- pure unit tests, run in the default suite.

The curated export whitelist used to live in `tests/infra/test_db_integration.py`
(integration-marked, so excluded from the default run); it had been red
since `text` and `update` were added to the surface, and nobody noticed
until the re-audit proved that the exported `text()` reproduced the
J-INFRA-05 exploit class: `session.execute(text("SELECT set_config(
'app.tenant_id', :t, false)"))` inside a tenant-scoped session reads
another tenant's rows and, with `is_local=false`, poisons the pooled
connection past COMMIT. The whitelist now lives here, in the normal
validation suite, and `text` is asserted absent the same way `func` is
(`tests/infra/test_db_orm.py`): not merely unlisted, but unimportable.
`update` stays -- `control_plane.approvals`' CP-01 atomic execution claim
is a compare-and-set `UPDATE` over an ORM-mapped table, which expresses
no function call. `tests/infra/db/test_func_export_removed_integration.py`
proves the same removal end-to-end against real PostgreSQL.
"""

from __future__ import annotations

from typing import cast

import pytest
from sqlalchemy import Table
from sqlalchemy import text as _real_sqlalchemy_text
from sqlalchemy import update as _real_sqlalchemy_update
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex

# --- The curated whitelist (moved from the integration-only file) ----------


def test_no_raw_connection_is_available_outside_the_chokepoint() -> None:
    """docs/MULTI-TENANCY.md section 3 / Acceptance Criteria: 'no other
    module can obtain a raw connection' -- `infra/db` exposes
    `get_engine()`, `session_scope()` and `tenant_session_scope()` as its
    only session/connection entrypoints; everything else is schema
    definition (`Base`, mixins, column types, constraints), two narrowed
    SQL functions (`now`, `sum_`), the two statement constructors ORM
    callers need (`select`, and `update` for CP-01's compare-and-set
    claim), the RLS DDL generator, the startup role guard, the migration
    runner, and the one named advisory-lock primitive. No generic SQL
    text constructor (`text`), no `func`, nothing that hands out a bare
    connection or lets a caller rewrite a session setting."""
    import infra.db as infra_db

    assert set(infra_db.__all__) == {
        "DatabaseConfig",
        "DatabaseConfigurationError",
        "get_database_config",
        "get_migrations_database_config",
        "run_core_migrations",
        "build_engine",
        "get_engine",
        "build_session_factory",
        "get_session_factory",
        "session_scope",
        "tenant_session_scope",
        "acquire_tenant_advisory_lock",
        "Session",
        "Base",
        "UUIDPrimaryKeyMixin",
        "TimestampMixin",
        "Mapped",
        "mapped_column",
        "String",
        "Text",
        "Integer",
        "Numeric",
        "Boolean",
        "DateTime",
        "ForeignKey",
        "ForeignKeyConstraint",
        "UniqueConstraint",
        "CheckConstraint",
        "Index",
        "JSON",
        "now",
        "sum_",
        "select",
        "update",
        "IntegrityError",
        "OperationalError",
        "tenant_rls_statements",
        "validate_application_role",
        "ApplicationRoleValidation",
        "UnsafeDatabaseRoleError",
    }


# --- `text` is gone, not hidden ---------------------------------------------


@pytest.mark.parametrize("module_name", ["infra.db", "infra.db.orm"])
def test_text_is_not_listed_and_not_an_attribute(module_name: str) -> None:
    import importlib

    module = importlib.import_module(module_name)
    assert "text" not in module.__all__
    assert not hasattr(module, "text")


def test_from_infra_db_import_text_fails() -> None:
    """The actual public API, not `__all__`: the exact import line the
    re-audit's exploit used must raise."""
    with pytest.raises(ImportError):
        from infra.db import text  # noqa: F401  # pyright: ignore[reportAttributeAccessIssue]


def test_from_infra_db_orm_import_text_fails() -> None:
    with pytest.raises(ImportError):
        from infra.db.orm import text  # noqa: F401  # pyright: ignore[reportAttributeAccessIssue]


def test_no_exported_name_is_or_produces_a_raw_sql_text_clause() -> None:
    """Exhaustive over the real surface: no export *is* `sqlalchemy.text`
    under another name, and calling any exported callable with a SQL
    string never yields an executable `TextClause` -- the shape a
    `set_config` exploit needs. (Model column types accept strings but
    produce types, not statements.)"""
    from sqlalchemy.sql.elements import TextClause

    import infra.db

    probe = "SELECT set_config('app.tenant_id', 'x', false)"
    for name in infra.db.__all__:
        obj = getattr(infra.db, name)
        assert obj is not _real_sqlalchemy_text, f"infra.db.{name} aliases sqlalchemy.text"
        if not callable(obj):
            continue
        try:
            produced = obj(probe)
        except Exception:  # noqa: BLE001 -- refusing the string is the safe outcome
            continue
        assert not isinstance(produced, TextClause), (
            f"infra.db.{name}({probe!r}) produced an executable TextClause"
        )


# --- What legitimately remains ----------------------------------------------


def test_update_is_the_real_sqlalchemy_update_for_cp01() -> None:
    """CP-01's atomic execution claim keeps working: `infra.db.update` is
    the genuine statement constructor, not a stub."""
    import infra.db

    assert infra.db.update is _real_sqlalchemy_update


def test_model_partial_index_predicates_need_no_text_export() -> None:
    """Non-vacuous proof that the four production partial unique indexes
    (`core/rbac/models.py`, `core/identity/models.py`) compile to exactly
    the DDL they did with `text(...)`, now that they pass the predicate as
    a plain string -- a string is coerced to DDL text at `CREATE INDEX`
    time and can never be executed through a session."""
    from core.identity.models import Invitation
    from core.rbac.models import DelegationGrant, DenyGrant, SupportAccessRequest

    expected = {
        "uq_delegation_grants_active_unique": "WHERE revoked_at IS NULL",
        "uq_deny_grants_active_unique": "WHERE revoked_at IS NULL",
        "uq_support_access_requests_live_unique": "WHERE denied_at IS NULL AND revoked_at IS NULL",
        "uq_invitations_live_unique": "WHERE accepted_at IS NULL AND revoked_at IS NULL",
    }
    seen: dict[str, str] = {}
    for model in (DelegationGrant, DenyGrant, SupportAccessRequest, Invitation):
        for index in cast(Table, model.__table__).indexes:
            if index.name in expected:
                ddl = str(CreateIndex(index).compile(dialect=postgresql.dialect()))
                seen[index.name] = ddl
                assert index.unique
                assert ddl.rstrip().endswith(expected[index.name]), ddl
                assert isinstance(index.dialect_options["postgresql"]["where"], str)
    assert set(seen) == set(expected)
