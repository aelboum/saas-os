"""require platform audit evidence for every tenant audit identity hold change

Revision ID: e1f5a8c3b7d9
Revises: d4f8b2e6a9c1
Create Date: 2026-11-16 12:00:00.000000

Audit identity phase P3c, `docs/architecture/AUDIT-IDENTITY-P3-PLAN.md`
(approved by the owner on 2026-11-15; scope item 5 and acceptance criterion
5, confirmed by the owner on 2026-11-16). Migration `c7e3a9f2b4d8` (P3a)
created `core.audit_identity_holds`, the tenant hold table, without an
evidence check, because nothing wrote it. P3c places and releases tenant
holds, so this migration adds the check that `b6d2f8a4c1e7` added for the
platform table.

A **deferred constraint trigger** (`AFTER INSERT OR UPDATE`, `DEFERRABLE
INITIALLY DEFERRED`, so it runs at commit) refuses a tenant hold row unless:

- `placed_by_platform_audit_id` names a `core.platform_audit_log` row with
  action `platform.audit_identity.hold_place`, outcome `success`, target
  type `audit_identity_hold`, target id the hold's id and target tenant the
  hold's tenant; and
- once released, `released_by_platform_audit_id` names such a row with
  action `platform.audit_identity.hold_release`.

**Why it can see the platform audit log.** A tenant hold is changed in one
transaction of ADR-0045 section 9c: the hold and the tenant audit row with
the tenant bound, then, with no tenant bound, the platform audit row. The
tenant binding is transaction-local and restored to `''` when its block
ends, so at commit no tenant is bound and the tenant-context exclusion
policy (ADR-0045 section 9b, decision D1) lets the trigger read
`core.platform_audit_log`. A hold committed while a tenant is still bound
cannot see that log, so it is refused: the check fails closed. No policy,
privilege or role changes; the function is not SECURITY DEFINER and pins
`search_path`; it runs for every role, the migrations role included.

A violation raises `foreign_key_violation` (`23503`) and the whole
transaction rolls back. It checks that evidence exists; it does not stop a
holder of the application credential from writing a matching platform audit
row itself, the residual risk the hold design accepts (owner decision O8):
such a row is in the platform audit log and its ADR-0053 digests.

**Existing rows.** Nothing wrote the table before this phase. The upgrade
still checks every row against the same rule and refuses to finish if one
fails, naming no row. The table is under FORCE row-level security and no
tenant is bound here, so the check lifts it inside this transaction and
restores `ENABLE` and `FORCE` before the transaction ends (as the
`c7e3a9f2b4d8` downgrade does); a refusal rolls the lift back with the rest.

**Locks and data safety.** The lift takes ACCESS EXCLUSIVE on
`core.audit_identity_holds` (a small table nothing else writes yet) until
commit; `CREATE FUNCTION` and `CREATE CONSTRAINT TRIGGER` take nothing more
on it, and no lock is taken on `core.platform_audit_log`. `lock_timeout` is
5s, as in `b6d2f8a4c1e7`. No row, grant or audit row changes.

**Downgrade** drops the trigger and its function; it loses no data.
Hand-written.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "e1f5a8c3b7d9"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "d4f8b2e6a9c1"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Static SQL only (no formatted identifiers): the evidence rule is spelled out
# in each statement.
_LIFT_RLS = (
    "ALTER TABLE core.audit_identity_holds NO FORCE ROW LEVEL SECURITY",
    "ALTER TABLE core.audit_identity_holds DISABLE ROW LEVEL SECURITY",
)
_RESTORE_RLS = (
    "ALTER TABLE core.audit_identity_holds ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE core.audit_identity_holds FORCE ROW LEVEL SECURITY",
)

_CHECK_EXISTING_ROWS = """
DO $$ BEGIN
IF EXISTS (
    SELECT 1 FROM core.audit_identity_holds h
     WHERE NOT EXISTS (
               SELECT 1 FROM core.platform_audit_log a
                WHERE a.id = h.placed_by_platform_audit_id
                  AND a.action = 'platform.audit_identity.hold_place'
                  AND a.outcome = 'success'
                  AND a.target_type = 'audit_identity_hold'
                  AND a.target_id = h.id::text
                  AND a.target_tenant_id = h.tenant_id)
        OR (h.released_by_platform_audit_id IS NOT NULL
            AND NOT EXISTS (
                SELECT 1 FROM core.platform_audit_log a
                 WHERE a.id = h.released_by_platform_audit_id
                   AND a.action = 'platform.audit_identity.hold_release'
                   AND a.outcome = 'success'
                   AND a.target_type = 'audit_identity_hold'
                   AND a.target_id = h.id::text
                   AND a.target_tenant_id = h.tenant_id))
) THEN
    RAISE EXCEPTION 'core.audit_identity_holds has a row without its platform audit evidence; '
        'refusing to add the evidence check. See docs/RUNBOOKS.md, audit identity holds.';
END IF;
END $$
"""

_CREATE_FUNCTION = """
CREATE FUNCTION core.audit_identity_holds_evidence()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM core.platform_audit_log a
         WHERE a.id = NEW.placed_by_platform_audit_id
           AND a.action = 'platform.audit_identity.hold_place'
           AND a.outcome = 'success'
           AND a.target_type = 'audit_identity_hold'
           AND a.target_id = NEW.id::text
           AND a.target_tenant_id = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'a tenant audit identity hold needs the platform audit row that placed it'
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF NEW.released_by_platform_audit_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM core.platform_audit_log a
         WHERE a.id = NEW.released_by_platform_audit_id
           AND a.action = 'platform.audit_identity.hold_release'
           AND a.outcome = 'success'
           AND a.target_type = 'audit_identity_hold'
           AND a.target_id = NEW.id::text
           AND a.target_tenant_id = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'a released tenant audit identity hold needs its releasing platform '
            'audit row' USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NULL;
END $$
"""

_CREATE_TRIGGER = """
CREATE CONSTRAINT TRIGGER trg_audit_identity_holds_evidence
AFTER INSERT OR UPDATE ON core.audit_identity_holds
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION core.audit_identity_holds_evidence()
"""


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '5s'")
    for statement in _LIFT_RLS:
        op.execute(statement)
    op.execute(_CHECK_EXISTING_ROWS)
    for statement in _RESTORE_RLS:
        op.execute(statement)
    op.execute(_CREATE_FUNCTION)
    op.execute(_CREATE_TRIGGER)


def downgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute("DROP TRIGGER trg_audit_identity_holds_evidence ON core.audit_identity_holds")
    op.execute("DROP FUNCTION core.audit_identity_holds_evidence()")
