"""Shared setup for the integration tests of the permission grant ledger's
approval mechanism (owner decisions of 2026-11-02 and 2026-11-03;
`docs/architecture/LEDGER-DELETION-APPROVAL-DESIGN.md`).

`Approvals` builds the people of the mechanism as real platform operators
holding exactly their permissions, issues them real sessions (the evidence
the platform-admin route hands Core), designates a representative through
the two-party register writes, enrols approvers, and makes tenants whose
ledger rows are old enough to expire (the real purge, its purge row moved
back three years with the privileged role).

The register's 120-day delay is real: `make_eligible` moves an enrolment's
`eligible_from` into the past with the privileged role in
`session_replication_role = replica` (the append-only trigger refuses every
UPDATE otherwise), which is test setup only. `cleanup` removes every row the
four approval tables hold the same way, before the platform tables are
emptied: the migration's downgrade refuses while any row exists, and the
shared CI database runs downgrade tests after these.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from platform_helpers import BOOTSTRAP, PlatformWorld
from sqlalchemy import text
from test_permission_grant_ledger_retention_integration import Ledger

from saas_os.core.authority import UserCaller
from saas_os.core.identity import issue_session
from saas_os.core.permission_grants import (
    RegisterEntryView,
    approve_permission_grant_ledger_deletion,
    authorize_permission_grant_ledger_deletion_execution,
    confirm_representative_designation,
    enrol_approver,
    place_permission_grant_ledger_hold,
    propose_representative_designation,
    release_permission_grant_ledger_hold,
    request_permission_grant_ledger_deletion,
)
from saas_os.core.platform_authority import (
    PlatformPermission,
    PlatformSessionEvidence,
    grant_platform_permission,
)

P = PlatformPermission
REASON = "integration test: ledger deletion approval"
APPROVAL_TABLES = (
    "core.permission_grant_ledger_deletion_execution_authorizations",
    "core.permission_grant_ledger_deletion_approvals",
    "core.permission_grant_ledger_deletion_requests",
    "core.permission_grant_ledger_approver_register",
)


class Approvals:
    """The people of one test, and the register entries that make the
    approver and the authoriser eligible."""

    def __init__(self, ledger: Ledger, platform: PlatformWorld) -> None:
        self.ledger = ledger
        self.platform = platform
        # A platform owner (authority) who also reports, as the bootstrap
        # owner does; an independent security operator (hold management
        # only); a representative, a requester, an approver and an
        # authoriser (report only); an auditor (audit read only).
        self.owner, self.owner_operator = platform.operator(
            [P.AUTHORITY_MANAGE, P.SECURITY_RETENTION_REPORT]
        )
        self.security, _ = platform.operator([P.SECURITY_RETENTION_HOLD_MANAGE])
        self.representative, _ = platform.operator([P.SECURITY_RETENTION_REPORT])
        self.requester, _ = platform.operator([P.SECURITY_RETENTION_REPORT])
        self.approver, _ = platform.operator([P.SECURITY_RETENTION_REPORT])
        self.authorizer, _ = platform.operator([P.SECURITY_RETENTION_REPORT])
        self.auditor, _ = platform.operator([P.AUDIT_READ])
        self.designation: RegisterEntryView | None = None
        self.enrolments: dict[uuid.UUID, RegisterEntryView] = {}

    # --- sessions -----------------------------------------------------------------

    def evidence(
        self, caller: UserCaller, *, multi_factor: bool = True, required: bool = True
    ) -> PlatformSessionEvidence:
        """A real session of `caller`, as the platform-admin chain would hand
        it to Core."""
        record, _token = issue_session(caller.user_id, multi_factor=multi_factor)
        return PlatformSessionEvidence(session_id=record.id, multi_factor_required=required)

    # --- privileged setup -----------------------------------------------------------

    def privileged(self, *statements: tuple[str, dict[str, Any]]) -> None:
        """Statements in one transaction of the privileged role with the
        ordinary triggers off (`session_replication_role = replica`)."""
        with self.platform.admin.begin() as conn:
            conn.execute(text("SET LOCAL session_replication_role = replica"))
            for sql, params in statements:
                conn.execute(text(sql), params)

    def make_eligible(self, entry_id: uuid.UUID) -> None:
        """Move an enrolment's 120-day delay into the past (test setup)."""
        self.privileged(
            (
                "UPDATE core.permission_grant_ledger_approver_register "
                "SET eligible_from = now() - interval '1 day' WHERE id = :i",
                {"i": entry_id},
            )
        )

    def cleanup(self) -> None:
        self.privileged(*((f"DELETE FROM {table}", {}) for table in APPROVAL_TABLES))  # noqa: S608

    # --- the register -----------------------------------------------------------------

    def designate(self, representative: UserCaller | None = None) -> RegisterEntryView:
        """A platform owner proposes, the independent security operator
        confirms."""
        subject = representative or self.representative
        proposal = propose_representative_designation(
            subject.user_id,
            caller=self.owner,
            session_evidence=self.evidence(self.owner),
            designation_ref="BOARD-RES-2026-11",
            ticket_ref="TICKET-21",
            valid_until=self.in_months(11),
            reason=REASON,
        )
        designation = confirm_representative_designation(
            subject.user_id,
            proposal.id,
            caller=self.security,
            session_evidence=self.evidence(self.security),
            ticket_ref="TICKET-22",
            reason=REASON,
        )
        if representative is None:
            self.designation = designation
        return designation

    def enrol(
        self,
        subject: UserCaller,
        person: str,
        *,
        eligible: bool = True,
        representative: UserCaller | None = None,
        **kwargs: Any,
    ) -> RegisterEntryView:
        by = representative or self.representative
        entry = enrol_approver(
            subject.user_id,
            caller=by,
            session_evidence=self.evidence(by),
            natural_person_ref=person,
            verification_ref=f"VERIFY-{person}",
            authorisation_ref=f"AUTH-{person}",
            ticket_ref="TICKET-23",
            valid_until=kwargs.pop("valid_until", self.in_months(11)),
            reason=kwargs.pop("reason", REASON),
            **kwargs,
        )
        if eligible:
            self.make_eligible(entry.id)
        self.enrolments[subject.user_id] = entry
        return entry

    def register_both(self) -> None:
        """The representative designated; the approver and the authoriser
        enrolled as two distinct verified persons, eligible now."""
        self.designate()
        self.enrol(self.approver, "PERSON-A")
        self.enrol(self.authorizer, "PERSON-B")

    def in_months(self, months: int) -> datetime:
        now = self.platform.scalar("SELECT now()")
        return now + timedelta(days=30 * months)

    # --- tenants, holds -------------------------------------------------------------------

    def expired(self, migrations: int = 1) -> uuid.UUID:
        tenant = self.ledger.tenant(migrations=migrations)
        self.ledger.purge(tenant)
        self.platform.execute(
            "UPDATE core.platform_audit_log SET created_at = created_at - interval '3 years' "
            "WHERE action = 'platform.tenant.purge_transition' AND target_tenant_id = :t "
            "AND metadata->>'to_status' = 'purged'",
            {"t": tenant},
        )
        return tenant

    def hold(self, tenant: uuid.UUID, reference: str = "LEGAL-77") -> Any:
        return place_permission_grant_ledger_hold(
            tenant, reference=reference, caller=self.ledger.holder, reason=REASON
        )

    def release(self, hold_id: uuid.UUID, caller: UserCaller | None = None) -> Any:
        by = caller or self.ledger.holder
        return release_permission_grant_ledger_hold(
            hold_id, caller=by, reason=REASON, session_evidence=self.evidence(by)
        )

    # --- the chain ----------------------------------------------------------------------

    def request(self, *tenants: uuid.UUID, caller: UserCaller | None = None, **kw: Any) -> Any:
        by = caller or self.requester
        report = self.ledger.report(*tenants)
        return request_permission_grant_ledger_deletion(
            caller=by,
            session_evidence=kw.pop("session_evidence", None) or self.evidence(by),
            tenant_ids=list(tenants),
            eligible_ledger_rows=kw.pop("rows", report.eligible_ledger_rows),
            eligible_digest=kw.pop("digest", report.eligible_digest),
            reason=kw.pop("reason", REASON),
        )

    def approve(self, request: Any, caller: UserCaller | None = None, **kw: Any) -> Any:
        by = caller or self.approver
        return approve_permission_grant_ledger_deletion(
            request.id,
            caller=by,
            session_evidence=kw.pop("session_evidence", None) or self.evidence(by),
            eligible_ledger_rows=kw.pop("rows", request.eligible_ledger_rows),
            eligible_digest=kw.pop("digest", request.eligible_digest),
            reason=kw.pop("reason", REASON),
        )

    def authorize(self, request: Any, caller: UserCaller | None = None, **kw: Any) -> Any:
        by = caller or self.authorizer
        return authorize_permission_grant_ledger_deletion_execution(
            request.id,
            caller=by,
            session_evidence=kw.pop("session_evidence", None) or self.evidence(by),
            reason=kw.pop("reason", REASON),
        )

    def grant(self, operator_id: uuid.UUID, permission: PlatformPermission) -> None:
        grant_platform_permission(operator_id, permission, caller=BOOTSTRAP, reason=REASON)

    def operator_id(self, caller: UserCaller) -> uuid.UUID:
        return self.platform.scalar(
            "SELECT id FROM core.platform_operators WHERE user_id = :u", {"u": caller.user_id}
        )

    def denied(self, action: str) -> list[str]:
        return [row["reason"] for row in self.platform.audit(action, "denied")]

    def count(self, table: str) -> int:
        return self.platform.scalar(f"SELECT count(*) FROM {table}")  # noqa: S608
