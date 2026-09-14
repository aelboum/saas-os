"""add RLS to core.invitations table

Revision ID: cb7120cfa806
Revises: a8ad8e61deb2
Create Date: 2026-09-14 00:00:00.000000

Privacy Architecture Audit finding PRIV-01 (MEDIUM): `core.invitations`
is genuinely tenant-owned (a real, required `tenant_id` column) but was
never RLS-protected -- unlike every other genuinely tenant-owned table in
the schema, it relied entirely on the application remembering to filter
`WHERE tenant_id = :tenant_id` in every query, with no database-level
backstop against a future missing filter.

**Scope decision, made explicitly rather than applying the same fix
blindly to `core.api_keys`** (the other table PRIV-01 named): a live,
disposable-PostgreSQL test proved that `ENABLE`/`FORCE ROW LEVEL
SECURITY` + the standard strict `tenant_id = app.tenant_id` policy makes
*every* query against the table -- from *any* function, regardless of
which other call sites are updated -- return zero rows whenever
`app.tenant_id` is unset, because RLS is enforced per-table/per-session,
not per-call-site. Both `core.api_keys` (`validate_api_key()`) and
`core.invitations` (`accept_invitation()`) have exactly one function that
must resolve a row by a bearer-secret hash *before* any tenant context
exists -- the whole point of a bearer credential. `core.api_keys`'s
`validate_api_key()` is live, production authentication; breaking it is
not acceptable in this remediation. `core.invitations`'s
`accept_invitation()`, by contrast, has no HTTP route calling it anywhere
in this codebase today (confirmed by the Privacy Architecture Audit) --
its own docstring already documents it as incomplete, deferred to a
future "Phase 8 ingress layer" for the email-correspondence check PRIV-07
separately identified. Applying RLS here, and accepting that
`accept_invitation()`'s token-resolution step (already dead code in
production) stops functioning until that future ingress work restructures
it, has zero current production impact and closes the real, live risk
this table's other four functions (`create_invitation`, `get_invitation`,
`list_invitations_for_tenant`, `revoke_invitation` -- all of which
already receive `tenant_id` as a parameter before they query anything)
carry today: a future missing `WHERE tenant_id = ...` mistake on any of
them, with no RLS backstop to catch it.

`core.api_keys` is deliberately left unchanged by this migration --
tracked as an explicit, documented scope reduction from PRIV-01's
original two-table framing, not an oversight (see this migration's own
module docstring above and the corresponding PRIV-01 implementation
report for the full empirical justification).

Runs via the privileged bootstrap/migration role
(`infra.db.config.get_migrations_database_config()`,
`MIGRATIONS_DATABASE_URL`) -- never the restricted application runtime
role, exactly like every migration since Phase 3.1.
"""

from collections.abc import Sequence

from alembic import op
from infra.db.rls import tenant_rls_statements

# revision identifiers, used by Alembic.
revision: str = "cb7120cfa806"
down_revision: str | Sequence[str] | None = "a8ad8e61deb2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "invitations"
_SCHEMA = "core"
_POLICY_NAME = f"{_TABLE}_tenant_isolation"


def upgrade() -> None:
    for statement in tenant_rls_statements(_TABLE, schema=_SCHEMA):
        op.execute(statement)


def downgrade() -> None:
    op.execute(f'DROP POLICY "{_POLICY_NAME}" ON "{_SCHEMA}"."{_TABLE}"')
    op.execute(f'ALTER TABLE "{_SCHEMA}"."{_TABLE}" NO FORCE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{_SCHEMA}"."{_TABLE}" DISABLE ROW LEVEL SECURITY')
