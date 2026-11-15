"""require platform audit evidence for every audit identity hold change

Revision ID: b6d2f8a4c1e7
Revises: e8a3c6f1d9b4
Create Date: 2026-11-14 12:00:00.000000

Audit identity phase P2 (docs/architecture/AUDIT-USER-IDENTIFIER-RETENTION-
PROPOSAL.md section 4.9; owner decisions D4 and O8). Phase P1 created
`core.platform_audit_identity_holds` (migration `e2b7c4d9a1f6`) with no
database-level check that a hold's placing and releasing audit ids name real
audit rows: a bug or a compromised application role could write or release a
hold with a dangling audit id, and nothing would show it (deferred-issue
ledger, "Legal-hold rows ... have no database-level authority or integrity
check"). P2 places and releases holds, so this migration adds that check.

A **deferred constraint trigger** on the hold table (`AFTER INSERT OR UPDATE`,
`DEFERRABLE INITIALLY DEFERRED`, so it runs at commit, after the audit row of
the same transaction is written) refuses a hold row unless:

- `placed_by_platform_audit_id` names a `core.platform_audit_log` row with
  action `platform.audit_identity.hold_place`, outcome `success`, target type
  `audit_identity_hold` and target id the hold's id; and
- once released, `released_by_platform_audit_id` names such a row with action
  `platform.audit_identity.hold_release`.

A violation raises `foreign_key_violation` (`23503`) and the whole
transaction rolls back. The function is not SECURITY DEFINER and pins
`search_path`; it runs for every role, the migrations role included. It
checks that evidence exists; it does not stop a holder of the application
credential from writing a matching audit row itself. That is the residual
risk the hold design accepts (owner decision O8): such a row is in the
platform audit log and its ADR-0053 digests.

Existing rows. Nothing wrote the hold table before this phase. The upgrade
still checks every existing row against the same rule and refuses to finish
if one fails, naming no row.

Locks and data safety. `CREATE FUNCTION` and `CREATE CONSTRAINT TRIGGER`
take `SHARE ROW EXCLUSIVE` on `core.platform_audit_identity_holds` only (no
lock on `core.platform_audit_log`); `lock_timeout` is 5s, as in
`e2b7c4d9a1f6`. No row changes, no grant changes, no audit row or digest is
touched.

Downgrade drops the trigger and its function; it loses no data. Hand-written.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "b6d2f8a4c1e7"  # pragma: allowlist secret
down_revision: str | Sequence[str] | None = "e8a3c6f1d9b4"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Static SQL only (no formatted identifiers): the evidence rule is spelled out
# in each statement.
_CHECK_EXISTING_ROWS = """
DO $$ BEGIN
IF EXISTS (
    SELECT 1 FROM core.platform_audit_identity_holds h
     WHERE NOT EXISTS (
               SELECT 1 FROM core.platform_audit_log a
                WHERE a.id = h.placed_by_platform_audit_id
                  AND a.action = 'platform.audit_identity.hold_place'
                  AND a.outcome = 'success'
                  AND a.target_type = 'audit_identity_hold'
                  AND a.target_id = h.id::text)
        OR (h.released_by_platform_audit_id IS NOT NULL
            AND NOT EXISTS (
                SELECT 1 FROM core.platform_audit_log a
                 WHERE a.id = h.released_by_platform_audit_id
                   AND a.action = 'platform.audit_identity.hold_release'
                   AND a.outcome = 'success'
                   AND a.target_type = 'audit_identity_hold'
                   AND a.target_id = h.id::text))
) THEN
    RAISE EXCEPTION 'core.platform_audit_identity_holds has a row without its platform audit '
        'evidence; refusing to add the evidence check. See docs/RUNBOOKS.md, audit identity holds.';
END IF;
END $$
"""

_CREATE_FUNCTION = """
CREATE FUNCTION core.platform_audit_identity_holds_evidence()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM core.platform_audit_log a
         WHERE a.id = NEW.placed_by_platform_audit_id
           AND a.action = 'platform.audit_identity.hold_place'
           AND a.outcome = 'success'
           AND a.target_type = 'audit_identity_hold'
           AND a.target_id = NEW.id::text
    ) THEN
        RAISE EXCEPTION 'an audit identity hold needs the platform audit row that placed it'
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF NEW.released_by_platform_audit_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM core.platform_audit_log a
         WHERE a.id = NEW.released_by_platform_audit_id
           AND a.action = 'platform.audit_identity.hold_release'
           AND a.outcome = 'success'
           AND a.target_type = 'audit_identity_hold'
           AND a.target_id = NEW.id::text
    ) THEN
        RAISE EXCEPTION 'a released audit identity hold needs its releasing platform audit row'
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NULL;
END $$
"""

_CREATE_TRIGGER = """
CREATE CONSTRAINT TRIGGER trg_platform_audit_identity_holds_evidence
AFTER INSERT OR UPDATE ON core.platform_audit_identity_holds
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION core.platform_audit_identity_holds_evidence()
"""


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute(_CHECK_EXISTING_ROWS)
    op.execute(_CREATE_FUNCTION)
    op.execute(_CREATE_TRIGGER)


def downgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '5s'")
    op.execute(
        "DROP TRIGGER trg_platform_audit_identity_holds_evidence "
        "ON core.platform_audit_identity_holds"
    )
    op.execute("DROP FUNCTION core.platform_audit_identity_holds_evidence()")
