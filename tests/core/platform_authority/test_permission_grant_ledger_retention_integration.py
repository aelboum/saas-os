"""Retention of the permission grant ledger (owner policy of 2026-11-02):
the eligibility report against the real purge, legal holds, the tombstone
requirement, refusals and unauthorised deletion, and isolation. PostgreSQL.

Nothing here deletes a ledger row: no runtime Core path can (the deletion
is the manual migrations-role procedure of owner decision B, tested in
`test_permission_grant_ledger_expiry_integration.py`). The tests show that
the rows stay, that the runtime role cannot delete them, when the report
would call them eligible, and that the report and the holds each need
their own least-privilege permission (owner decision A of 2026-11-02).

Every test names its tenants (an `all_purged` report starts just before
the test's own tenant, so tombstones other tests left are never in the
way). Cleanup: the test's ledger rows, holds and registered permissions
are deleted with the privileged role; `Scene` turns the tenants into
tombstones; `PlatformWorld` empties the platform tables.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, timedelta

import pytest
from phase_c_helpers import PROVISIONING, TENANT_PURGE, Scene
from platform_helpers import PlatformWorld
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from saas_os.api.platform_bootstrap import BOOTSTRAP_PERMISSIONS
from saas_os.core.authority import ServiceAccountCaller, UserCaller
from saas_os.core.identity import issue_session
from saas_os.core.permission_grants import (
    InvalidLedgerRetentionRequestError,
    LedgerHoldAlreadyActiveError,
    LedgerHoldAlreadyReleasedError,
    LedgerHoldNotFoundError,
    LedgerHoldTenantNotFoundError,
    PermissionGrantMigration,
    RetentionStatus,
    apply_permission_grant_migrations,
    permission_grant_ledger_retention_report,
    place_permission_grant_ledger_hold,
    release_permission_grant_ledger_hold,
    retention_expires_at,
)
from saas_os.core.platform_authority import (
    PlatformNotAuthorizedError,
    PlatformPermission,
    PlatformSessionEvidence,
)
from saas_os.core.rbac import create_role, register_permission
from saas_os.core.tenancy import TenantStatus, purge_tenant
from saas_os.core.tenancy.purge_participants import TenantPurgeParticipantRegistry
from saas_os.infra.db import session_scope, tenant_session_scope

pytestmark = pytest.mark.integration

P = PlatformPermission
NS = "grt_ret"
REASON = "integration test: ledger retention"
REPORT = "platform.permission_grant_ledger.retention_report"
PLACE = "platform.permission_grant_ledger.hold_place"
RELEASE = "platform.permission_grant_ledger.hold_release"


class Ledger:
    """Tenants with permission grant ledger rows, for one test."""

    def __init__(self, scene: Scene, platform: PlatformWorld) -> None:
        self.scene = scene
        self.platform = platform
        self.resource = f"grt_{uuid.uuid4().hex[:10]}.report"
        self.permission = register_permission(self.resource, "read")
        # Least privilege (owner decision A): one person applies the grant
        # migrations, another reports, a third places and releases holds.
        self.operator = platform.operator([P.PERMISSION_GRANT_APPLY])[0]
        self.reporter = platform.operator([P.SECURITY_RETENTION_REPORT])[0]
        self.holder = platform.operator([P.SECURITY_RETENTION_HOLD_MANAGE])[0]

    def tenant(self, migrations: int = 1) -> uuid.UUID:
        """An ACTIVE tenant with an `admin` role and `migrations` ledger rows."""
        tenant = self.scene.tenant(active=True)
        create_role(tenant, "admin", caller=PROVISIONING)
        declared = [
            PermissionGrantMigration(
                f"2026-11-m{index}", NS, "admin", ((self.resource, "read"),), "retention test"
            )
            for index in range(migrations)
        ]
        apply_permission_grant_migrations(
            declared,
            namespace=NS,
            caller=self.operator,
            reason=REASON,
            tenant_ids=[tenant],
            apply=True,
        )
        assert self.rows(tenant) == migrations
        return tenant

    def purge(self, tenant: uuid.UUID) -> None:
        """The real purge: `DELETED`, then `purge_tenant()`, which writes the
        `PURGING -> PURGED` platform row in the transition's transaction."""
        self.scene.set_status(tenant, TenantStatus.DELETED)
        purge_tenant(tenant, caller=TENANT_PURGE, registry=TenantPurgeParticipantRegistry())
        assert self.scene.status(tenant) == TenantStatus.PURGED.value

    def purge_time(self, tenant: uuid.UUID):  # type: ignore[no-untyped-def]
        return self.platform.scalar(
            "SELECT created_at FROM core.platform_audit_log "
            "WHERE action = 'platform.tenant.purge_transition' AND target_tenant_id = :t "
            "AND metadata->>'to_status' = 'purged'",
            {"t": tenant},
        )

    def rows(self, tenant: uuid.UUID) -> int:
        return self.platform.scalar(
            "SELECT count(*) FROM core.permission_grant_applications WHERE tenant_id = :t",
            {"t": tenant},
        )

    def report(self, *tenants: uuid.UUID, caller: object = None, **kwargs):  # type: ignore[no-untyped-def]
        return permission_grant_ledger_retention_report(
            caller=caller if caller is not None else self.reporter,
            reason=REASON,
            tenant_ids=list(tenants),
            **kwargs,
        )

    def cleanup(self) -> None:
        if self.scene.tenants:
            params = {"t": self.scene.tenants}
            self.platform.execute(
                "DELETE FROM core.permission_grant_ledger_holds WHERE target_tenant_id = ANY(:t)",
                params,
            )
            self.platform.execute(
                "DELETE FROM core.permission_grant_applications WHERE tenant_id = ANY(:t)", params
            )
        self.platform.execute(
            "DELETE FROM core.role_permissions WHERE permission_id = :p", {"p": self.permission.id}
        )
        self.platform.execute(
            "DELETE FROM core.permissions WHERE resource = :r", {"r": self.resource}
        )


@pytest.fixture
def ledger(scene: Scene, platform: PlatformWorld) -> Iterator[Ledger]:
    built = Ledger(scene, platform)
    try:
        yield built
    finally:
        built.cleanup()


def _evidence(caller: UserCaller) -> PlatformSessionEvidence:
    """A real session of `caller`, as the platform-admin route hands it to
    Core: a hold is released only through that route (owner decision of
    2026-11-03), and Core checks the session against storage."""
    record, _token = issue_session(caller.user_id, multi_factor=True)
    return PlatformSessionEvidence(session_id=record.id, multi_factor_required=True)


def _place(ledger: Ledger, tenant: uuid.UUID, reference: str = "LEGAL-2026-014"):  # type: ignore[no-untyped-def]
    return place_permission_grant_ledger_hold(
        tenant, reference=reference, caller=ledger.holder, reason=REASON
    )


# --- eligibility against the real purge -------------------------------------------


def test_the_real_purge_starts_two_years_a_hold_blocks_and_its_release_allows(
    ledger: Ledger, platform: PlatformWorld
) -> None:
    tenant = ledger.tenant(migrations=2)
    ledger.purge(tenant)
    purged_at = ledger.purge_time(tenant)
    expires_at = retention_expires_at(purged_at)

    (now,) = ledger.report(tenant).tenants
    assert now.status is RetentionStatus.RETENTION_RUNNING
    assert (now.purged_at, now.expires_at, now.ledger_rows) == (purged_at, expires_at, 2)

    (before,) = ledger.report(tenant, as_of=expires_at - timedelta(microseconds=1)).tenants
    assert before.status is RetentionStatus.RETENTION_RUNNING
    (exactly,) = ledger.report(tenant, as_of=expires_at).tenants
    assert exactly.status is RetentionStatus.ELIGIBLE

    hold = _place(ledger, tenant)
    (held,) = ledger.report(tenant, as_of=expires_at + timedelta(days=1)).tenants
    assert held.status is RetentionStatus.LEGAL_HOLD and held.active_holds == 1

    released = release_permission_grant_ledger_hold(
        hold.hold_id, caller=ledger.holder, reason=REASON, session_evidence=_evidence(ledger.holder)
    )
    assert released.released_at is not None
    report = ledger.report(tenant, as_of=expires_at + timedelta(days=1))
    assert report.tenants[0].status is RetentionStatus.ELIGIBLE
    assert report.eligible_ledger_rows == 2

    # Eligible is a decision, not a deletion: every row is still there.
    assert ledger.rows(tenant) == 2
    # The hold row stays as history, with both platform rows' ids.
    stored = platform.execute(
        "SELECT reference, placed_by_platform_audit_id, released_by_platform_audit_id, "
        "released_at IS NOT NULL FROM core.permission_grant_ledger_holds WHERE id = :h",
        {"h": hold.hold_id},
    )
    assert stored == [("LEGAL-2026-014", hold.platform_audit_id, released.platform_audit_id, True)]
    placed_row = platform.execute(
        "SELECT action, target_tenant_id, outcome, actor_user_id FROM core.platform_audit_log "
        "WHERE id = :i",
        {"i": hold.platform_audit_id},
    )
    assert placed_row == [(PLACE, tenant, "success", ledger.holder.user_id)]
    released_row = platform.execute(
        "SELECT action, target_tenant_id, outcome FROM core.platform_audit_log WHERE id = :i",
        {"i": released.platform_audit_id},
    )
    assert released_row == [(RELEASE, tenant, "success")]
    # One success row per report; counts and statuses only, no names.
    reports = platform.audit(REPORT, "success")
    assert len(reports) == 5
    last = reports[-1]["metadata"]
    assert last["tenants_eligible"] == 1 and last["eligible_ledger_rows"] == 2
    assert last["as_of_overridden"] is True and last["retention_years"] == 2
    # The overriding time is recorded, in UTC (review finding 4).
    assert last["as_of"] == (expires_at + timedelta(days=1)).astimezone(UTC).isoformat()
    assert reports[0]["metadata"]["as_of"] is None
    assert ledger.resource not in str(reports) and "admin" not in str(reports)


def test_an_all_purged_report_pages_in_id_order(ledger: Ledger) -> None:
    tenant = ledger.tenant()
    ledger.purge(tenant)
    report = ledger.report(all_purged=True, after=uuid.UUID(int=tenant.int - 1), limit=1)
    assert [t.tenant_id for t in report.tenants] == [tenant]
    assert report.tenants[0].status is RetentionStatus.RETENTION_RUNNING


# --- the tombstone is required ------------------------------------------------------


def test_no_tenant_is_eligible_without_its_purged_tombstone_and_purge_evidence(
    ledger: Ledger, scene: Scene, platform: PlatformWorld
) -> None:
    future = {"as_of": _far_future()}
    open_tenant = ledger.tenant()
    deleted = ledger.tenant()
    scene.set_status(deleted, TenantStatus.DELETED)
    missing = uuid.uuid4()
    report = ledger.report(open_tenant, deleted, missing, **future)
    statuses = {t.tenant_id: (t.status, t.ledger_rows) for t in report.tenants}
    assert statuses == {
        open_tenant: (RetentionStatus.NOT_PURGED, 1),
        deleted: (RetentionStatus.NOT_PURGED, 1),
        missing: (RetentionStatus.TENANT_NOT_FOUND, 0),
    }

    # A tombstone with no purge row (a purge recorded before the platform
    # row existed, or a status set by hand) has no known purge time.
    no_evidence = ledger.tenant()
    scene.set_status(no_evidence, TenantStatus.PURGED)
    (unknown,) = ledger.report(no_evidence, **future).tenants
    assert unknown.status is RetentionStatus.PURGE_TIME_UNKNOWN

    # A second, back-dated purge row cannot advance the expiry.
    purged = ledger.tenant()
    ledger.purge(purged)
    platform.execute(
        "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
        "target_type, target_id, target_tenant_id, outcome, metadata, created_at) VALUES "
        "(:i, 'system', 'tenant_purge', 'platform.tenant.purge_transition', 'tenant', :s, :t, "
        "'success', CAST(:m AS json), now() - interval '10 years')",
        {
            "i": uuid.uuid4(),
            "s": str(purged),
            "t": purged,
            "m": '{"from_status": "purging", "to_status": "purged"}',
        },
    )
    (ambiguous,) = ledger.report(purged, **future).tenants
    assert ambiguous.status is RetentionStatus.PURGE_TIME_AMBIGUOUS
    for tenant in (open_tenant, deleted, no_evidence, purged):
        assert ledger.rows(tenant) == 1


def _far_future():  # type: ignore[no-untyped-def]
    from datetime import UTC, datetime

    return datetime(2100, 1, 1, tzinfo=UTC)


# --- refusals ------------------------------------------------------------------------


def test_callers_without_the_permission_are_refused_and_recorded(
    ledger: Ledger, platform: PlatformWorld
) -> None:
    tenant = ledger.tenant()
    hold = _place(ledger, tenant)
    others = [
        platform.operator([P.TENANT_READ, P.AUDIT_READ])[0],
        # `platform.permission_grant:apply` grants neither (owner decision A).
        ledger.operator,
        UserCaller(platform.user()),  # not an operator
        ServiceAccountCaller(tenant, uuid.uuid4()),
        TENANT_PURGE,
    ]
    platform.clear_audit()
    for caller in others:
        with pytest.raises((PlatformNotAuthorizedError, TypeError)):
            ledger.report(tenant, caller=caller)
        assert ledger.rows(tenant) == 1
        with pytest.raises((PlatformNotAuthorizedError, TypeError)):
            place_permission_grant_ledger_hold(
                tenant, reference="LEGAL-9", caller=caller, reason=REASON
            )
        with pytest.raises((PlatformNotAuthorizedError, TypeError)):
            release_permission_grant_ledger_hold(
                hold.hold_id, caller=caller, reason=REASON, session_evidence=None
            )
    assert platform.audit(outcome="success") == []
    denied = platform.audit(outcome="denied")
    assert {row["action"] for row in denied} == {REPORT, PLACE, RELEASE}
    assert {row["reason"] for row in denied} == {"not_authorized"}
    # Nothing changed: the one hold is still the only one, still active.
    assert platform.execute(
        "SELECT reference, released_at FROM core.permission_grant_ledger_holds "
        "WHERE target_tenant_id = :t",
        {"t": tenant},
    ) == [("LEGAL-2026-014", None)]


def test_hold_requests_that_cannot_apply_are_refused_with_a_code(
    ledger: Ledger, platform: PlatformWorld
) -> None:
    tenant = ledger.tenant()
    platform.clear_audit()
    with pytest.raises(LedgerHoldTenantNotFoundError):
        _place(ledger, uuid.uuid4())
    with pytest.raises(InvalidLedgerRetentionRequestError):
        _place(ledger, tenant, "John Smith")  # a name is never a reference
    hold = _place(ledger, tenant)
    with pytest.raises(LedgerHoldAlreadyActiveError):
        _place(ledger, tenant)
    evidence = _evidence(ledger.holder)
    released = release_permission_grant_ledger_hold(
        hold.hold_id, caller=ledger.holder, reason=REASON, session_evidence=evidence
    )
    # The same release retried (same caller, same reason) is a replay; any
    # other second release is refused (owner decisions of 2026-11-03).
    replayed = release_permission_grant_ledger_hold(
        hold.hold_id, caller=ledger.holder, reason=REASON, session_evidence=evidence
    )
    assert replayed.replay is True and replayed.platform_audit_id == released.platform_audit_id
    with pytest.raises(LedgerHoldAlreadyReleasedError):
        release_permission_grant_ledger_hold(
            hold.hold_id,
            caller=ledger.holder,
            reason="integration test: a second release",
            session_evidence=evidence,
        )
    with pytest.raises(LedgerHoldNotFoundError):
        release_permission_grant_ledger_hold(
            uuid.uuid4(), caller=ledger.holder, reason=REASON, session_evidence=evidence
        )
    again = _place(ledger, tenant)  # the reference may be held again once released
    assert again.hold_id != hold.hold_id
    codes = sorted(row["reason"] for row in platform.audit(outcome="denied"))
    assert codes == [
        "hold_already_active",
        "hold_already_released",
        "hold_not_found",
        "invalid_request",
        "tenant_not_found",
    ]


# --- unauthorised deletion ------------------------------------------------------------


def test_the_runtime_role_cannot_delete_the_ledger_or_a_hold_or_rewrite_a_hold(
    ledger: Ledger,
) -> None:
    tenant = ledger.tenant()
    ledger.purge(tenant)
    hold = _place(ledger, tenant)
    with (
        pytest.raises(ProgrammingError, match="permission denied"),
        tenant_session_scope(tenant) as session,
    ):
        session.execute(text("DELETE FROM core.permission_grant_applications"))
    with pytest.raises(ProgrammingError, match="permission denied"), session_scope() as session:
        session.execute(text("DELETE FROM core.permission_grant_applications"))
    with pytest.raises(ProgrammingError, match="permission denied"), session_scope() as session:
        session.execute(text("DELETE FROM core.permission_grant_ledger_holds"))
    with pytest.raises(ProgrammingError, match="permission denied"), session_scope() as session:
        session.execute(
            text("UPDATE core.permission_grant_ledger_holds SET reference = 'X' WHERE id = :h"),
            {"h": hold.hold_id},
        )
    with pytest.raises(ProgrammingError, match="permission denied"), session_scope() as session:
        session.execute(text("TRUNCATE core.permission_grant_ledger_holds"))
    assert ledger.rows(tenant) == 1


# --- isolation --------------------------------------------------------------------------


def test_holds_are_invisible_to_a_tenant_scope_and_one_tenant_never_affects_another(
    ledger: Ledger, platform: PlatformWorld
) -> None:
    held, free = ledger.tenant(migrations=2), ledger.tenant()
    ledger.purge(held)
    ledger.purge(free)
    _place(ledger, held)
    with tenant_session_scope(held) as session:
        visible = session.execute(
            text("SELECT count(*) FROM core.permission_grant_ledger_holds")
        ).scalar_one()
    assert visible == 0
    with (
        pytest.raises(ProgrammingError, match="row-level security"),
        tenant_session_scope(held) as session,
    ):
        session.execute(
            text(
                "INSERT INTO core.permission_grant_ledger_holds (id, target_tenant_id, "
                "reference, placed_by_platform_audit_id) VALUES (:i, :t, 'LEGAL-X', :a)"
            ),
            {"i": uuid.uuid4(), "t": held, "a": uuid.uuid4()},
        )
    report = ledger.report(held, free, as_of=_far_future())
    statuses = {t.tenant_id: (t.status, t.ledger_rows, t.active_holds) for t in report.tenants}
    assert statuses == {
        held: (RetentionStatus.LEGAL_HOLD, 2, 1),
        free: (RetentionStatus.ELIGIBLE, 1, 0),
    }


# --- least privilege (owner decision A of 2026-11-02) --------------------------------


def test_each_retention_permission_allows_exactly_its_own_operations(
    ledger: Ledger, platform: PlatformWorld
) -> None:
    """`platform.security_retention:report` reports and nothing else;
    `platform.security_retention_hold:manage` places and releases holds and
    nothing else; `platform.permission_grant:apply` does neither, and
    neither retention permission applies grant migrations."""
    tenant = ledger.tenant()
    hold = _place(ledger, tenant)
    holder_session = _evidence(ledger.holder)
    platform.clear_audit()

    # The reporter reports; it can neither place nor release a hold.
    assert ledger.report(tenant, caller=ledger.reporter).tenants[0].tenant_id == tenant
    with pytest.raises(PlatformNotAuthorizedError):
        place_permission_grant_ledger_hold(
            tenant, reference="LEGAL-R", caller=ledger.reporter, reason=REASON
        )
    with pytest.raises(PlatformNotAuthorizedError):
        release_permission_grant_ledger_hold(
            hold.hold_id, caller=ledger.reporter, reason=REASON, session_evidence=None
        )

    # The holder places and releases; it cannot report.
    with pytest.raises(PlatformNotAuthorizedError):
        ledger.report(tenant, caller=ledger.holder)
    second = _place(ledger, tenant, "LEGAL-H")
    release_permission_grant_ledger_hold(
        second.hold_id, caller=ledger.holder, reason=REASON, session_evidence=holder_session
    )

    # `:apply` alone: no report, no hold, no release.
    with pytest.raises(PlatformNotAuthorizedError):
        ledger.report(tenant, caller=ledger.operator)
    with pytest.raises(PlatformNotAuthorizedError):
        place_permission_grant_ledger_hold(
            tenant, reference="LEGAL-A", caller=ledger.operator, reason=REASON
        )
    with pytest.raises(PlatformNotAuthorizedError):
        release_permission_grant_ledger_hold(
            hold.hold_id, caller=ledger.operator, reason=REASON, session_evidence=None
        )

    # Neither retention permission applies grant migrations.
    declared = [
        PermissionGrantMigration("2026-11-lp", NS, "admin", ((ledger.resource, "read"),), "lp")
    ]
    for caller in (ledger.reporter, ledger.holder):
        with pytest.raises(PlatformNotAuthorizedError):
            apply_permission_grant_migrations(
                declared,
                namespace=NS,
                caller=caller,
                reason=REASON,
                tenant_ids=[tenant],
                apply=True,
            )
    assert ledger.rows(tenant) == 1

    successes = [(row["action"], row["actor_user_id"]) for row in platform.audit(outcome="success")]
    assert successes == [
        (REPORT, ledger.reporter.user_id),
        (PLACE, ledger.holder.user_id),
        (RELEASE, ledger.holder.user_id),
    ]
    denied = {(row["action"], row["actor_user_id"]) for row in platform.audit(outcome="denied")}
    assert denied == {
        (PLACE, ledger.reporter.user_id),
        (RELEASE, ledger.reporter.user_id),
        (REPORT, ledger.holder.user_id),
        (REPORT, ledger.operator.user_id),
        (PLACE, ledger.operator.user_id),
        (RELEASE, ledger.operator.user_id),
        ("platform.permission_grant.apply", ledger.reporter.user_id),
        ("platform.permission_grant.apply", ledger.holder.user_id),
    }
    # The first hold is still active; the second was released.
    assert platform.execute(
        "SELECT reference, released_at IS NULL FROM core.permission_grant_ledger_holds "
        "WHERE target_tenant_id = :t ORDER BY reference",
        {"t": tenant},
    ) == [("LEGAL-2026-014", True), ("LEGAL-H", False)]


def test_an_operator_holding_the_bootstrap_list_cannot_place_or_release_a_hold(
    ledger: Ledger, platform: PlatformWorld
) -> None:
    """Separation of duties (owner decision of 2026-11-02): the first
    owner's permissions, exactly as bootstrap grants them, report but never
    place or release a legal hold; only the independently authorised hold
    manager does, and the release names that person, not the owner."""
    assert P.SECURITY_RETENTION_HOLD_MANAGE not in BOOTSTRAP_PERMISSIONS
    owner = platform.operator(BOOTSTRAP_PERMISSIONS)[0]
    tenant = ledger.tenant()
    hold = _place(ledger, tenant)
    platform.clear_audit()
    assert ledger.report(tenant, caller=owner).tenants[0].tenant_id == tenant
    with pytest.raises(PlatformNotAuthorizedError):
        place_permission_grant_ledger_hold(tenant, reference="LEGAL-O", caller=owner, reason=REASON)
    with pytest.raises(PlatformNotAuthorizedError):
        release_permission_grant_ledger_hold(
            hold.hold_id, caller=owner, reason=REASON, session_evidence=None
        )
    assert platform.execute(
        "SELECT released_at FROM core.permission_grant_ledger_holds WHERE id = :h",
        {"h": hold.hold_id},
    ) == [(None,)]
    release_permission_grant_ledger_hold(
        hold.hold_id, caller=ledger.holder, reason=REASON, session_evidence=_evidence(ledger.holder)
    )
    released_by = platform.execute(
        "SELECT a.actor_user_id FROM core.permission_grant_ledger_holds h "
        "JOIN core.platform_audit_log a ON a.id = h.released_by_platform_audit_id "
        "WHERE h.id = :h",
        {"h": hold.hold_id},
    )
    assert released_by == [(ledger.holder.user_id,)]
    denied = {(row["action"], row["actor_user_id"]) for row in platform.audit(outcome="denied")}
    assert denied == {(PLACE, owner.user_id), (RELEASE, owner.user_id)}


def test_the_report_records_the_count_and_digest_a_deletion_must_confirm(
    ledger: Ledger, platform: PlatformWorld
) -> None:
    from saas_os.core.permission_grants import eligible_ledger_digest

    eligible, held = ledger.tenant(migrations=2), ledger.tenant()
    ledger.purge(eligible)
    ledger.purge(held)
    _place(ledger, held)
    report = ledger.report(eligible, held, as_of=_far_future())
    ids = [
        row[0]
        for row in platform.execute(
            "SELECT id FROM core.permission_grant_applications WHERE tenant_id = :t ORDER BY id",
            {"t": eligible},
        )
    ]
    assert report.eligible_ledger_rows == 2
    assert report.eligible_digest == eligible_ledger_digest({eligible: ids})
    # The digest covers only eligible rows: the held tenant's row is not in it.
    assert report.eligible_digest != eligible_ledger_digest({eligible: ids, held: [uuid.uuid4()]})
    metadata = platform.audit(REPORT, "success")[-1]["metadata"]
    assert metadata["eligible_digest"] == report.eligible_digest
    assert metadata["eligible_ledger_rows"] == 2
