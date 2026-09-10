"""Infra database connection/session foundation
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.1; docs/MULTI-TENANCY.md section 3;
tenant-scoping enforcement completed in Phase 3.1).

This is the platform's single database-access chokepoint: no other module
(Core, Product, Control Plane) constructs its own engine or opens its own
connection. Tenant-scoping *enforcement* is `tenant_session_scope()` (a
PostgreSQL session variable RLS policies check) plus `rls.tenant_rls_statements()`
(the DDL a tenant-owned table's migration applies) -- both added in Phase
3.1 alongside `core/tenancy`, the first module to need them.

`infra/db` intentionally does not import from `core/` -- Infrastructure
depends on nothing above it (docs/ARCHITECTURE.md section 2). Its own
database configuration is sourced through `infra.secrets.get_secrets_provider()`
(docs/IMPLEMENTATION-ROADMAP.md Phase 2.3) -- `infra/db` depends on
`infra/secrets`'s public `SecretsProvider` interface only, never a
concrete provider implementation directly. Two distinct configs, since
Phase 3.1's security correction: `get_database_config()` (`DATABASE_URL`)
is the restricted application runtime role `session_scope()`/
`tenant_session_scope()` use; `get_migrations_database_config()`
(`MIGRATIONS_DATABASE_URL`) is the separate, privileged bootstrap/
migration role Alembic uses -- PostgreSQL never applies Row-Level
Security to a superuser or a BYPASSRLS role, so these must never be the
same role (see `infra/db/config.py`'s docstring).

`role_guard.validate_application_role()` (P1.2) is a startup-time,
fail-closed check that the running application's actual runtime role
(`get_database_config()`/`get_engine()`) is demonstrably neither a
superuser nor BYPASSRLS -- defense in depth around the role-separation
property this module's docstring already documents, not a replacement
for it. See that module's own docstring.

`infra/db` defines no business schema itself (docs/ARCHITECTURE.md section
2: "Infrastructure has zero knowledge of business concepts") -- `orm.Base`
and its mixins are pure SQLAlchemy mechanics that Core/Product modules use
to define their *own* tables (docs/DATA-ARCHITECTURE.md section 1),
without those modules ever importing `sqlalchemy` directly themselves
(`pyproject.toml`'s "Only infra/db may import SQLAlchemy or psycopg
directly" contract). See `infra/db/migrations/` for the Alembic migration
environment itself, and `infra/db/migration_runner.py`
(`run_core_migrations()`, re-exported here) -- the supported, importable
way to invoke it (docs/ADR/0016); also reachable via the `saas-os-migrate`
console script (`infra/db/migration_cli.py`).
"""

from infra.db.config import (
    DatabaseConfig,
    DatabaseConfigurationError,
    get_database_config,
    get_migrations_database_config,
)
from infra.db.engine import build_engine, get_engine
from infra.db.migration_runner import run_core_migrations
from infra.db.orm import (
    JSON,
    Base,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    IntegrityError,
    Mapped,
    Numeric,
    OperationalError,
    String,
    Text,
    TimestampMixin,
    UniqueConstraint,
    UUIDPrimaryKeyMixin,
    func,
    mapped_column,
    select,
)
from infra.db.rls import tenant_rls_statements
from infra.db.role_guard import (
    ApplicationRoleValidation,
    UnsafeDatabaseRoleError,
    validate_application_role,
)
from infra.db.session import (
    Session,
    acquire_tenant_advisory_lock,
    build_session_factory,
    get_session_factory,
    session_scope,
    tenant_session_scope,
)

__all__ = [
    "DatabaseConfig",
    "DatabaseConfigurationError",
    "get_database_config",
    "get_migrations_database_config",
    "build_engine",
    "get_engine",
    "run_core_migrations",
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
    "func",
    "select",
    "IntegrityError",
    "OperationalError",
    "tenant_rls_statements",
    "validate_application_role",
    "ApplicationRoleValidation",
    "UnsafeDatabaseRoleError",
]
