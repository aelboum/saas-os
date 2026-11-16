"""Audit identity phase P3c against a real PostgreSQL: legal holds on tenant
audit references and the tenant scope of the expiry plan, report and command
(docs/architecture/AUDIT-IDENTITY-P3-PLAN.md, scope items 5 and 6;
migration `e1f5a8c3b7d9`).

What is asserted, on the stored rows:

- placing a tenant hold writes the hold in the tenant's own table, one row in
  the tenant's audit trail and one platform row naming the tenant, all in
  one transaction; a duplicate, an unknown tenant and a caller without the
  permission are refused; the same matter in another tenant or the platform
  scope is another hold;
- a release takes no scope: the tenant is read from the platform row that
  placed the hold; it happens once; a tenant's list shows its holds only;
- the deferred evidence trigger refuses a tenant hold without its platform
  row, with the row of another tenant, and -- failing closed -- one committed
  while a tenant is still bound, even when the right row exists; the same
  insert committed with no tenant bound is accepted;
- erasure keeps a link a tenant hold covers;
- the tenant dry run reports exactly the eligible sets, with the record bound
  over the three identifying keys, holds and markers, other tenants and the
  platform scope left out; the application-role report equals it; a missing
  or invalid phase P3b index refuses the plan; the record-bound queries can
  use the indexes;
- `apply` is refused while the gate is off; with the gate on in-process, a
  matching confirmation expires the tenant's links and markers with start,
  scope and finish rows, and touches no other tenant.

Links, markers and audit rows are made with the privileged role. Marked
`integration`; the reference tables are emptied after each test body
(`tests/conftest.py`), and the tenants made here are removed afterwards.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from platform_helpers import REASON, PlatformWorld
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

import saas_os.core.audit_identity.expiry as expiry
from lifecycle_callers import PROVISIONING
from saas_os.core.audit_identity import (
    AuditIdentityExpiryDisabledError,
    AuditIdentityHoldAlreadyActiveError,
    AuditIdentityHoldAlreadyReleasedError,
    AuditIdentityHoldTenantNotFoundError,
    AuditIdentityIndexUnavailableError,
    hold_set_digest,
    list_audit_identity_holds,
    place_audit_identity_hold,
    reference_set_digest,
    release_audit_identity_hold,
)
from saas_os.core.audit_identity.expiry import ExpiryConfirmation, expire_audit_identity_links
from saas_os.core.audit_identity.plan import (
    tenant_audit_identity_expiry_report,
    tenant_reference_use_queries,
)
from saas_os.core.audit_log.subjects import erase_tenant_audit_subject
from saas_os.core.authority import UserCaller
from saas_os.core.identity import issue_session
from saas_os.core.platform_authority import (
    PlatformNotAuthorizedError,
    PlatformPermission,
    PlatformSessionEvidence,
)
from saas_os.core.tenancy import create_tenant
from saas_os.infra.db import bind_tenant_scope, session_scope, tenant_session_scope

pytestmark = pytest.mark.integration

P = PlatformPermission
PLACE = "platform.audit_identity.hold_place"
RELEASE = "platform.audit_identity.hold_release"
EXPIRY = "platform.audit_identity.expiry"
TICKET = "TICKET-10: tenant audit identity expiry"
OLD_DAY = date(2020, 3, 10)  # day bound passed long ago
_INDEXES = ("ix_audit_log_initiated_by_subject_ref", "ix_audit_log_owner_user_subject_ref")


class World:
    """Operators, two tenants, users and privileged setup for one test."""

    def __init__(self, platform: PlatformWorld) -> None:
        self.platform = platform
        self.holder = platform.operator([P.SECURITY_RETENTION_HOLD_MANAGE])[0]
        self.reporter = platform.operator([P.SECURITY_RETENTION_REPORT])[0]
        self.tenants = [
            create_tenant(f"p3c-{uuid.uuid4().hex[:8]}", caller=PROVISIONING).id for _ in (1, 2)
        ]

    @property
    def tenant(self) -> uuid.UUID:
        return self.tenants[0]

    @property
    def other(self) -> uuid.UUID:
        return self.tenants[1]

    def evidence(self, caller: UserCaller) -> PlatformSessionEvidence:
        record, _token = issue_session(caller.user_id, multi_factor=True)
        return PlatformSessionEvidence(session_id=record.id, multi_factor_required=True)

    def link(
        self, tenant: uuid.UUID, user_id: uuid.UUID | None, day: date, *, unlinked: bool = False
    ) -> uuid.UUID:
        ref = uuid.uuid4()
        if unlinked or user_id is None:
            self.platform.execute(
                "INSERT INTO core.audit_subject_links (subject_ref, tenant_id, user_id, "
                "subject_day, unlinked_at, unlink_reason) "
                "VALUES (:r, :t, NULL, :d, now(), 'erasure')",
                {"r": ref, "t": tenant, "d": day},
            )
        else:
            self.platform.execute(
                "INSERT INTO core.audit_subject_links (subject_ref, tenant_id, user_id, "
                "subject_day) VALUES (:r, :t, :u, :d)",
                {"r": ref, "t": tenant, "u": user_id, "d": day},
            )
        return ref

    def marker(self, tenant: uuid.UUID, user_id: uuid.UUID, erased_at: datetime) -> None:
        self.platform.execute(
            "INSERT INTO core.audit_subject_erasures (tenant_id, user_id, erased_at) "
            "VALUES (:t, :u, :e)",
            {"t": tenant, "u": user_id, "e": erased_at},
        )

    def referencing_row(
        self, tenant: uuid.UUID, ref: uuid.UUID, created_at: datetime, *, key: str
    ) -> None:
        """A tenant audit row that carries `ref` as user identification under
        `key`: `initiated_by`, `owner_user_subject_ref` or
        `operator_user_subject_ref`."""
        metadata: dict[str, object]
        if key == "initiated_by":
            metadata = {"initiated_by": {"type": "user", "subject_ref": str(ref)}}
        else:
            metadata = {key: str(ref)}
        self.platform.execute(
            "INSERT INTO core.audit_log (id, tenant_id, actor_type, action, resource_type, "
            "resource_id, outcome, metadata, created_at) VALUES (:i, :t, 'system', "
            "'test.reference', 'test_resource', :i2, 'success', CAST(:m AS json), :c)",
            {
                "i": uuid.uuid4(),
                "i2": str(uuid.uuid4()),
                "t": tenant,
                "m": json.dumps(metadata),
                "c": created_at,
            },
        )

    def link_row(self, ref: uuid.UUID) -> tuple[Any, ...] | None:
        rows = self.platform.execute(
            "SELECT user_id, unlink_reason FROM core.audit_subject_links WHERE subject_ref = :r",
            {"r": ref},
        )
        return rows[0] if rows else None

    def markers(self, tenant: uuid.UUID) -> set[uuid.UUID]:
        return {
            row[0]
            for row in self.platform.execute(
                "SELECT user_id FROM core.audit_subject_erasures WHERE tenant_id = :t",
                {"t": tenant},
            )
        }

    def tenant_audit(self, tenant: uuid.UUID, action: str) -> list[tuple[Any, ...]]:
        return self.platform.execute(
            "SELECT resource_id, metadata FROM core.audit_log "
            "WHERE tenant_id = :t AND action = :a ORDER BY created_at",
            {"t": tenant, "a": action},
        )

    def dry_run(self, tenant: uuid.UUID) -> Any:
        return expire_audit_identity_links(caller=self.reporter, reason=TICKET, tenant_id=tenant)

    def confirmation(self, report: Any) -> ExpiryConfirmation:
        return ExpiryConfirmation(
            rows=report.eligible_links,
            digest=report.eligible_links_digest,
            holds=report.active_holds_digest,
            unlinks=report.links_to_unlink,
            markers=report.markers,
        )

    def cleanup(self) -> None:
        ids = [str(t) for t in self.tenants]
        self.platform.execute(
            "DELETE FROM core.audit_log WHERE tenant_id::text = ANY(:t) "
            "OR acting_as_tenant_id::text = ANY(:t)",
            {"t": ids},
        )
        self.platform.execute("TRUNCATE core.audit_identity_holds")
        self.platform.execute(
            "DELETE FROM core.platform_audit_log WHERE target_tenant_id::text = ANY(:t)",
            {"t": ids},
        )
        self.platform.execute("DELETE FROM core.tenants WHERE id::text = ANY(:t)", {"t": ids})


@pytest.fixture
def world(platform: PlatformWorld) -> Iterator[World]:
    made = World(platform)
    try:
        yield made
    finally:
        made.cleanup()


@pytest.fixture
def apply_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """In-process only: the shipped constant stays `False` (owner decision O9)."""
    monkeypatch.setattr(expiry, "_APPLY_ENABLED", True)


def _now(world: World) -> datetime:
    return world.platform.scalar("SELECT now()")


def _sqlstate(error: DBAPIError) -> str | None:
    return getattr(error.orig, "sqlstate", None)


# --- holds ---------------------------------------------------------------------------------


def test_placing_a_tenant_hold_writes_the_hold_and_both_audit_rows(world: World) -> None:
    subject = uuid.uuid4()
    hold = place_audit_identity_hold(
        reference="LEGAL-2026-021",
        from_day=date(2026, 1, 1),
        subject_ref=subject,
        caller=world.holder,
        reason=REASON,
        tenant_id=world.tenant,
    )
    assert hold.scope == f"tenant:{world.tenant}"
    platform_rows = world.platform.execute(
        "SELECT id, target_id, target_tenant_id, metadata FROM core.platform_audit_log "
        "WHERE action = :a AND outcome = 'success'",
        {"a": PLACE},
    )
    assert len(platform_rows) == 1
    audit_id, target_id, target_tenant, metadata = platform_rows[0]
    assert (audit_id, target_id, target_tenant) == (
        hold.platform_audit_id,
        str(hold.hold_id),
        world.tenant,
    )
    assert metadata["scope"] == f"tenant:{world.tenant}"
    assert metadata["subject_ref"] == str(subject)
    stored = world.platform.execute(
        "SELECT tenant_id, placed_by_platform_audit_id, released_at "
        "FROM core.audit_identity_holds WHERE id = :h",
        {"h": hold.hold_id},
    )
    assert stored == [(world.tenant, hold.platform_audit_id, None)]
    tenant_rows = world.tenant_audit(world.tenant, "audit_identity.hold_place")
    assert len(tenant_rows) == 1
    assert tenant_rows[0][0] == str(hold.hold_id)
    assert tenant_rows[0][1]["platform"] is True
    assert tenant_rows[0][1]["reference"] == "LEGAL-2026-021"
    # Nothing in the platform scope's own hold table.
    assert world.platform.scalar("SELECT count(*) FROM core.platform_audit_identity_holds") == 0


def test_duplicates_unknown_tenants_and_unauthorized_callers_are_refused(world: World) -> None:
    place_audit_identity_hold(
        reference="LEGAL-1", caller=world.holder, reason=REASON, tenant_id=world.tenant
    )
    with pytest.raises(AuditIdentityHoldAlreadyActiveError):
        place_audit_identity_hold(
            reference="LEGAL-1", caller=world.holder, reason=REASON, tenant_id=world.tenant
        )
    # The same matter in another tenant, or in the platform scope, is another hold.
    place_audit_identity_hold(
        reference="LEGAL-1", caller=world.holder, reason=REASON, tenant_id=world.other
    )
    place_audit_identity_hold(reference="LEGAL-1", caller=world.holder, reason=REASON)
    with pytest.raises(AuditIdentityHoldTenantNotFoundError):
        place_audit_identity_hold(
            reference="LEGAL-2", caller=world.holder, reason=REASON, tenant_id=uuid.uuid4()
        )
    with pytest.raises(PlatformNotAuthorizedError):
        place_audit_identity_hold(
            reference="LEGAL-3", caller=world.reporter, reason=REASON, tenant_id=world.tenant
        )
    denied = [row["reason"] for row in world.platform.audit(action=PLACE, outcome="denied")]
    assert sorted(denied) == ["hold_already_active", "not_authorized", "tenant_not_found"]
    assert world.platform.scalar("SELECT count(*) FROM core.audit_identity_holds") == 2


def test_a_tenant_release_finds_its_tenant_and_happens_once(world: World) -> None:
    hold = place_audit_identity_hold(
        reference="LEGAL-4", caller=world.holder, reason=REASON, tenant_id=world.tenant
    )
    other = place_audit_identity_hold(
        reference="LEGAL-4", caller=world.holder, reason=REASON, tenant_id=world.other
    )
    platform_hold = place_audit_identity_hold(
        reference="LEGAL-4", caller=world.holder, reason=REASON
    )
    released = release_audit_identity_hold(
        hold.hold_id,
        caller=world.holder,
        reason=REASON,
        session_evidence=world.evidence(world.holder),
    )
    assert released.scope == f"tenant:{world.tenant}" and released.released_at is not None
    with pytest.raises(AuditIdentityHoldAlreadyReleasedError):
        release_audit_identity_hold(
            hold.hold_id,
            caller=world.holder,
            reason=REASON,
            session_evidence=world.evidence(world.holder),
        )
    stored = world.platform.execute(
        "SELECT released_by_platform_audit_id FROM core.audit_identity_holds WHERE id = :h",
        {"h": hold.hold_id},
    )
    assert stored == [(released.platform_audit_id,)]
    release_row = world.platform.execute(
        "SELECT target_tenant_id FROM core.platform_audit_log WHERE id = :i",
        {"i": released.platform_audit_id},
    )
    assert release_row == [(world.tenant,)]
    assert [r[0] for r in world.tenant_audit(world.tenant, "audit_identity.hold_release")] == [
        str(hold.hold_id)
    ]
    # Each scope lists its own holds only.
    mine = list_audit_identity_holds(caller=world.holder, tenant_id=world.tenant)
    assert [h.id for h in mine.holds] == [hold.hold_id]
    theirs = list_audit_identity_holds(caller=world.holder, tenant_id=world.other, active=True)
    assert [h.id for h in theirs.holds] == [other.hold_id]
    platform_page = list_audit_identity_holds(caller=world.holder)
    assert [h.id for h in platform_page.holds] == [platform_hold.hold_id]


def test_the_database_refuses_a_tenant_hold_without_its_evidence(world: World) -> None:
    with pytest.raises(DBAPIError) as missing:
        world.platform.execute(
            "INSERT INTO core.audit_identity_holds (id, tenant_id, reference, "
            "placed_by_platform_audit_id) VALUES (:i, :t, 'LEGAL-5', :a)",
            {"i": uuid.uuid4(), "t": world.tenant, "a": uuid.uuid4()},
        )
    assert _sqlstate(missing.value) == "23503"
    # A platform row for this hold id that names another tenant is not evidence.
    hold_id, audit_id = uuid.uuid4(), uuid.uuid4()
    world.platform.execute(
        "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
        "target_type, target_id, target_tenant_id, outcome) VALUES (:i, 'system', "
        "'platform_bootstrap', :a, 'audit_identity_hold', :h, :t, 'success')",
        {"i": audit_id, "a": PLACE, "h": str(hold_id), "t": world.other},
    )
    with pytest.raises(DBAPIError) as wrong_tenant:
        world.platform.execute(
            "INSERT INTO core.audit_identity_holds (id, tenant_id, reference, "
            "placed_by_platform_audit_id) VALUES (:i, :t, 'LEGAL-6', :a)",
            {"i": hold_id, "t": world.tenant, "a": audit_id},
        )
    assert _sqlstate(wrong_tenant.value) == "23503"
    # A release that names the placing row is refused too.
    hold = place_audit_identity_hold(
        reference="LEGAL-6", caller=world.holder, reason=REASON, tenant_id=world.tenant
    )
    with pytest.raises(DBAPIError) as wrong_release:
        world.platform.execute(
            "UPDATE core.audit_identity_holds SET released_at = now(), "
            "released_by_platform_audit_id = placed_by_platform_audit_id WHERE id = :h",
            {"h": hold.hold_id},
        )
    assert _sqlstate(wrong_release.value) == "23503"


def test_the_evidence_check_fails_closed_while_a_tenant_is_bound_at_commit(world: World) -> None:
    """The matching platform row exists, written by the privileged role. The
    application role inserts the hold: committed while the tenant is still
    bound, the trigger cannot see the platform audit log and refuses it;
    committed after the tenant scope ends (ADR-0045 section 9c), the same
    insert is accepted."""
    hold_id, audit_id = uuid.uuid4(), uuid.uuid4()
    world.platform.execute(
        "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
        "target_type, target_id, target_tenant_id, outcome) VALUES (:i, 'system', "
        "'platform_bootstrap', :a, 'audit_identity_hold', :h, :t, 'success')",
        {"i": audit_id, "a": PLACE, "h": str(hold_id), "t": world.tenant},
    )
    insert = text(
        "INSERT INTO core.audit_identity_holds (id, tenant_id, reference, "
        "placed_by_platform_audit_id) VALUES (:i, :t, 'LEGAL-7', :a)"
    )
    params = {"i": hold_id, "t": world.tenant, "a": audit_id}
    with pytest.raises(DBAPIError) as bound:  # noqa: PT012 -- the commit is what fails
        with tenant_session_scope(world.tenant) as session:
            session.execute(insert, params)
    assert _sqlstate(bound.value) == "23503"
    with session_scope() as session, bind_tenant_scope(session, world.tenant):
        session.execute(insert, params)
    count = world.platform.scalar(
        "SELECT count(*) FROM core.audit_identity_holds WHERE id = :h", {"h": hold_id}
    )
    assert count == 1


def test_erasure_keeps_a_link_a_tenant_hold_covers(world: World) -> None:
    user = world.platform.user()
    today = _now(world).astimezone(UTC).date()
    held = world.link(world.tenant, user, today)
    elsewhere = world.link(world.other, user, today)
    place_audit_identity_hold(
        reference="LEGAL-8",
        subject_ref=held,
        caller=world.holder,
        reason=REASON,
        tenant_id=world.tenant,
    )
    for tenant in world.tenants:
        with tenant_session_scope(tenant) as session:
            erase_tenant_audit_subject(session, tenant_id=tenant, user_id=user)
    assert world.link_row(held) == (user, None)  # kept under the tenant's hold
    assert world.link_row(elsewhere) == (None, "erasure")  # not the other tenant's hold


# --- the tenant plan -----------------------------------------------------------------------


def test_the_tenant_dry_run_reports_exactly_the_eligible_sets(world: World) -> None:
    now = _now(world)
    tenant = world.tenant
    a, b, erased, erased_held = (world.platform.user() for _ in range(4))
    eligible = world.link(tenant, a, OLD_DAY)
    eligible_unlinked = world.link(tenant, None, OLD_DAY, unlinked=True)
    recent = world.link(tenant, b, now.astimezone(UTC).date() - timedelta(days=700))
    by_initiator = world.link(tenant, a, OLD_DAY - timedelta(days=1))
    world.referencing_row(tenant, by_initiator, now - timedelta(days=30), key="initiated_by")
    by_owner = world.link(tenant, a, OLD_DAY - timedelta(days=2))
    world.referencing_row(tenant, by_owner, now - timedelta(days=30), key="owner_user_subject_ref")
    by_operator = world.link(tenant, a, OLD_DAY - timedelta(days=3))
    world.referencing_row(
        tenant, by_operator, now - timedelta(days=30), key="operator_user_subject_ref"
    )
    referenced_long_ago = world.link(tenant, b, OLD_DAY - timedelta(days=4))
    world.referencing_row(
        tenant, referenced_long_ago, now - timedelta(days=900), key="initiated_by"
    )
    # The same reference carried recently in *another* tenant does not extend it.
    world.referencing_row(world.other, eligible, now - timedelta(days=1), key="initiated_by")
    held = world.link(tenant, a, OLD_DAY - timedelta(days=5))
    place_audit_identity_hold(
        reference="LEGAL-9", subject_ref=held, caller=world.holder, reason=REASON, tenant_id=tenant
    )
    unheld_live = world.link(tenant, erased, now.astimezone(UTC).date())
    world.marker(tenant, erased, now - timedelta(days=800))
    held_live = world.link(tenant, erased_held, now.astimezone(UTC).date() - timedelta(days=1))
    place_audit_identity_hold(
        reference="LEGAL-10",
        subject_ref=held_live,
        caller=world.holder,
        reason=REASON,
        tenant_id=tenant,
    )
    world.marker(tenant, erased_held, now - timedelta(days=800))
    # Another tenant's rows are not this tenant's plan.
    world.link(world.other, a, OLD_DAY)
    world.marker(world.other, erased, now - timedelta(days=800))

    report = world.dry_run(tenant)

    scope = f"tenant:{tenant}"
    assert report.scope == scope
    expected = sorted([eligible, eligible_unlinked, referenced_long_ago])
    assert report.eligible_links == 3
    assert report.eligible_links_digest == reference_set_digest(scope, expected)
    assert report.links_to_unlink == 1
    assert report.markers == 1
    holds = world.platform.execute(
        "SELECT id FROM core.audit_identity_holds WHERE tenant_id = :t", {"t": tenant}
    )
    assert report.active_holds == 2
    assert report.active_holds_digest == hold_set_digest(scope, [h[0] for h in holds])
    assert report.oldest_eligible_day == OLD_DAY - timedelta(days=4)
    assert not report.applied
    for ref in (eligible, recent, by_initiator, by_owner, by_operator, held, unheld_live):
        assert world.link_row(ref) is not None
    assert world.platform.audit(action=EXPIRY) == []
    # The application-role report (the scheduled job) sees the same plan.
    job = tenant_audit_identity_expiry_report(tenant)
    assert {**job.__dict__, "as_of": None} == {**report.__dict__, "as_of": None}


@pytest.mark.parametrize("index", _INDEXES)
def test_an_invalid_index_refuses_the_tenant_plan(world: World, index: str) -> None:
    world.platform.execute(
        "UPDATE pg_index SET indisvalid = false WHERE indexrelid = to_regclass(:n)",
        {"n": f"core.{index}"},
    )
    try:
        with pytest.raises(AuditIdentityIndexUnavailableError) as refused:
            tenant_audit_identity_expiry_report(world.tenant)
        assert refused.value.index == index
        with pytest.raises(AuditIdentityIndexUnavailableError):
            world.dry_run(world.tenant)
    finally:
        world.platform.execute(
            "UPDATE pg_index SET indisvalid = true WHERE indexrelid = to_regclass(:n)",
            {"n": f"core.{index}"},
        )
    assert [row["reason"] for row in world.platform.audit(action=EXPIRY, outcome="denied")] == [
        "index_unavailable"
    ]
    # The platform scope does not need them.
    expire_audit_identity_links(caller=world.reporter, reason=TICKET)


@pytest.mark.parametrize(("position", "index"), [(0, _INDEXES[0]), (1, _INDEXES[1])])
def test_the_record_bound_queries_can_use_the_indexes(
    world: World, position: int, index: str
) -> None:
    references = [str(uuid.uuid4()), str(uuid.uuid4())]
    query = tenant_reference_use_queries(world.tenant, references)[position]
    with world.platform.admin.begin() as conn:
        conn.execute(text("SET LOCAL enable_seqscan = off"))
        compiled = str(query.compile(dialect=conn.dialect, compile_kwargs={"literal_binds": True}))
        plan = "\n".join(row[0] for row in conn.exec_driver_sql(f"EXPLAIN {compiled}"))
    assert index in plan, plan


# --- apply -----------------------------------------------------------------------------------


def test_tenant_apply_is_refused_while_the_gate_is_off(world: World) -> None:
    ref = world.link(world.tenant, world.platform.user(), OLD_DAY)
    report = world.dry_run(world.tenant)
    with pytest.raises(AuditIdentityExpiryDisabledError):
        expire_audit_identity_links(
            caller=world.reporter,
            reason=TICKET,
            apply=True,
            confirmation=world.confirmation(report),
            tenant_id=world.tenant,
        )
    assert world.link_row(ref) is not None
    assert world.platform.audit(action=EXPIRY) == []


def test_with_the_gate_on_a_tenant_run_expires_that_tenant_only(
    world: World, apply_enabled: None
) -> None:
    now = _now(world)
    old, erased = world.platform.user(), world.platform.user()
    eligible = world.link(world.tenant, old, OLD_DAY)
    live_of_erased = world.link(world.tenant, erased, now.astimezone(UTC).date())
    world.marker(world.tenant, erased, now - timedelta(days=800))
    other_eligible = world.link(world.other, old, OLD_DAY)
    world.marker(world.other, erased, now - timedelta(days=800))

    report = world.dry_run(world.tenant)
    assert (report.eligible_links, report.links_to_unlink, report.markers) == (1, 1, 1)
    applied = expire_audit_identity_links(
        caller=world.reporter,
        reason=TICKET,
        apply=True,
        confirmation=world.confirmation(report),
        tenant_id=world.tenant,
    )
    assert applied.applied and applied.scope == f"tenant:{world.tenant}"
    assert world.link_row(eligible) is None
    assert world.link_row(live_of_erased) == (None, "erasure")
    assert world.markers(world.tenant) == set()
    # The other tenant is untouched.
    assert world.link_row(other_eligible) is not None
    assert world.markers(world.other) == {erased}
    rows = world.platform.audit(action=EXPIRY, outcome="success")
    assert [row["metadata"]["phase"] for row in rows] == ["start", "scope", "finish"]
    assert rows[0]["metadata"]["scopes"] == [f"tenant:{world.tenant}"]
    assert rows[1]["metadata"]["scope"] == f"tenant:{world.tenant}"
    assert rows[1]["metadata"]["links_deleted_digest"] == report.eligible_links_digest
    again = world.dry_run(world.tenant)
    assert (again.eligible_links, again.links_to_unlink, again.markers) == (0, 0, 0)
