"""allow platform (system) revocation of support access grants

Revision ID: b7d2e4f6a8c0
Revises: f3a9c85e1b64
Create Date: 2026-09-15 00:00:00.000000

PRIV-03 Phase P6 (privacy re-audit finding RA-02): a `SupportAccessRequest`
is retained forever as security evidence (P1's restrictive FK, P4's
SECURITY_RETAIN classification), but the *authority* it lends must not
outlive the tenant that lent it. Tenant purge now revokes every live grant
(`core/rbac/service.py::revoke_tenant_support_access()`) before the tenant
reaches `PURGED` -- the row stays, `revoked_at` is set, `can()` can never
honor it again.

A purge may run with no human actor (`core.tenancy.purge_tenant()`'s
`actor_user_id=None`, recorded under the existing `ActorType.SYSTEM` audit
actor). The original `ck_support_access_requests_revocation_pairing`
(`9aecff1d1135`) required `revoked_by_user_id` whenever `revoked_at` is
set, so the schema could not represent a platform-performed revocation
at all. This migration relaxes that one CHECK to:

    revoked_by_user_id IS NULL OR revoked_at IS NOT NULL

i.e. a human revoker still always needs a revocation timestamp, but a
timestamp with no human revoker is now a valid state meaning "revoked by
the platform during tenant purge". Approval and denial pairing are
unchanged -- those decisions are only ever made by a person.
`ck_support_access_requests_revoke_requires_approval` is unchanged too: a
never-approved request is still never "revoked".

No data is modified, no column is added or removed, no RLS or grant
changes. Downgrade restores the strict pairing and therefore fails, by
design, if any platform-revoked row exists -- that evidence must not be
silently rewritten to fit the older constraint.

Runs via the privileged bootstrap/migration role
(`infra.db.config.get_migrations_database_config()`,
`MIGRATIONS_DATABASE_URL`) -- never the restricted application runtime
role, exactly like every migration since Phase 3.1.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7d2e4f6a8c0"
down_revision: str | Sequence[str] | None = "f3a9c85e1b64"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCHEMA = "core"
_TABLE = "support_access_requests"
_CONSTRAINT = "ck_support_access_requests_revocation_pairing"
_RELAXED = "revoked_by_user_id IS NULL OR revoked_at IS NOT NULL"
_STRICT = (
    "(revoked_at IS NULL AND revoked_by_user_id IS NULL) "
    "OR (revoked_at IS NOT NULL AND revoked_by_user_id IS NOT NULL)"
)


def upgrade() -> None:
    op.drop_constraint(_CONSTRAINT, _TABLE, schema=_SCHEMA, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, _RELAXED, schema=_SCHEMA)


def downgrade() -> None:
    op.drop_constraint(_CONSTRAINT, _TABLE, schema=_SCHEMA, type_="check")
    op.create_check_constraint(_CONSTRAINT, _TABLE, _STRICT, schema=_SCHEMA)
