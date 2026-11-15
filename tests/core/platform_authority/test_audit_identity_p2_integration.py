"""Audit identity phase P2 against a real PostgreSQL: legal holds on platform
audit references (owner decisions D4, O8 and the hold route permission) and
the expiry of links and erasure markers (D7, D8, O9, O10).

What is asserted, on the stored rows:

- placing and releasing a hold write one platform audit row each, in the
  hold's transaction, whose id the hold row records; a duplicate, a second
  release, a missing session and a caller without the permission are
  refused with one `denied` row; the database refuses a hold row without its
  audit evidence, and a released hold is never changed;
- the dry run reports exactly the eligible links (day bound, record bound
  over both identifying locations, holds), the links of erased subjects to
  unlink and the markers to delete, with the canonical digests; the
  application-role report equals it; the application role cannot delete;
- `apply` is refused while the gate is off; with the gate switched on
  in-process, a stale confirmation changes nothing, a matching one deletes,
  unlinks and deletes markers with start, scope and finish rows, and a rerun
  finds nothing;
- a held link survives expiry and erasure, and the first run after the
  release processes it (D4);
- after a marker expires a new write links the user again, a re-erasure
  makes a new marker, and a restored marker is found by the next run (O10).

Links, markers and audit rows are made old with the privileged role. Marked
`integration`; the `platform` fixture empties the platform tables.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from platform_helpers import REASON, PlatformWorld
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

import saas_os.core.audit_identity.expiry as expiry
from saas_os.core.audit_identity import (
    AuditIdentityExpiryConfirmationMismatchError,
    AuditIdentityExpiryDisabledError,
    AuditIdentityHoldAlreadyActiveError,
    AuditIdentityHoldAlreadyReleasedError,
    AuditIdentitySessionEvidenceError,
    audit_identity_expiry_report,
    hold_set_digest,
    list_audit_identity_holds,
    place_audit_identity_hold,
    reference_set_digest,
    release_audit_identity_hold,
)
from saas_os.core.audit_identity.expiry import ExpiryConfirmation, expire_audit_identity_links
from saas_os.core.authority import UserCaller
from saas_os.core.identity import issue_session
from saas_os.core.platform_authority import (
    PlatformNotAuthorizedError,
    PlatformPermission,
    PlatformSessionEvidence,
)
from saas_os.core.platform_authority.subjects import (
    erase_platform_audit_subject,
    platform_audit_subject_ref,
)
from saas_os.infra.db import session_scope

pytestmark = pytest.mark.integration

P = PlatformPermission
PLACE = "platform.audit_identity.hold_place"
RELEASE = "platform.audit_identity.hold_release"
EXPIRY = "platform.audit_identity.expiry"
TICKET = "TICKET-9: audit identity expiry"
OLD_DAY = date(2020, 3, 10)  # day bound passed long ago


class World:
    """Operators, users and privileged setup for one test."""

    def __init__(self, platform: PlatformWorld) -> None:
        self.platform = platform
        self.holder = platform.operator([P.SECURITY_RETENTION_HOLD_MANAGE])[0]
        self.reporter = platform.operator([P.SECURITY_RETENTION_REPORT])[0]

    def evidence(self, caller: UserCaller) -> PlatformSessionEvidence:
        record, _token = issue_session(caller.user_id, multi_factor=True)
        return PlatformSessionEvidence(session_id=record.id, multi_factor_required=True)

    def privileged(self, sql: str, params: dict[str, Any] | None = None) -> None:
        """One statement as the privileged role with the ordinary triggers off
        (test setup only: moving a link's day back, which the one-way trigger
        refuses for every role)."""
        with self.platform.admin.begin() as conn:
            conn.execute(text("SET LOCAL session_replication_role = replica"))
            conn.execute(text(sql), params or {})

    def link(self, user_id: uuid.UUID | None, day: date, *, unlinked: bool = False) -> uuid.UUID:
        ref = uuid.uuid4()
        if unlinked or user_id is None:
            self.platform.execute(
                "INSERT INTO core.platform_audit_subject_links "
                "(subject_ref, user_id, subject_day, unlinked_at, unlink_reason) "
                "VALUES (:r, NULL, :d, now(), 'erasure')",
                {"r": ref, "d": day},
            )
        else:
            self.platform.execute(
                "INSERT INTO core.platform_audit_subject_links (subject_ref, user_id, subject_day) "
                "VALUES (:r, :u, :d)",
                {"r": ref, "u": user_id, "d": day},
            )
        return ref

    def marker(self, user_id: uuid.UUID, erased_at: datetime) -> None:
        self.platform.execute(
            "INSERT INTO core.platform_audit_subject_erasures (user_id, erased_at) VALUES (:u, :e)",
            {"u": user_id, "e": erased_at},
        )

    def referencing_row(
        self, ref: uuid.UUID, created_at: datetime, *, in_metadata: bool = False
    ) -> None:
        """A platform audit row that carries `ref` as user identification."""
        if in_metadata:
            self.platform.execute(
                "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
                "target_type, target_id, outcome, metadata, created_at) VALUES (:i, 'system', "
                "'platform_bootstrap', 'platform.operator.enroll', 'platform_operator', :o, "
                "'success', CAST(:m AS json), :c)",
                {
                    "i": uuid.uuid4(),
                    "o": str(uuid.uuid4()),
                    "m": f'{{"user_subject_ref": "{ref}"}}',
                    "c": created_at,
                },
            )
        else:
            self.platform.execute(
                "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
                "target_type, target_id, outcome, created_at) VALUES (:i, 'system', "
                "'platform_bootstrap', 'platform.user.read', 'user_subject', :r, 'success', :c)",
                {"i": uuid.uuid4(), "r": str(ref), "c": created_at},
            )

    def link_row(self, ref: uuid.UUID) -> tuple[Any, ...] | None:
        rows = self.platform.execute(
            "SELECT user_id, unlink_reason FROM core.platform_audit_subject_links "
            "WHERE subject_ref = :r",
            {"r": ref},
        )
        return rows[0] if rows else None

    def markers(self) -> set[uuid.UUID]:
        return {
            row[0]
            for row in self.platform.execute(
                "SELECT user_id FROM core.platform_audit_subject_erasures"
            )
        }

    def dry_run(self) -> Any:
        return expire_audit_identity_links(caller=self.reporter, reason=TICKET)

    def confirmation(self, report: Any) -> ExpiryConfirmation:
        return ExpiryConfirmation(
            rows=report.eligible_links,
            digest=report.eligible_links_digest,
            holds=report.active_holds_digest,
            unlinks=report.links_to_unlink,
            markers=report.markers,
        )


@pytest.fixture
def world(platform: PlatformWorld) -> Iterator[World]:
    yield World(platform)


@pytest.fixture
def apply_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """In-process only: the shipped constant stays `False` (owner decision O9)."""
    monkeypatch.setattr(expiry, "_APPLY_ENABLED", True)


def _now(world: World) -> datetime:
    return world.platform.scalar("SELECT now()")


# --- holds ---------------------------------------------------------------------------------


def test_placing_a_hold_records_its_audit_row_in_the_same_transaction(world: World) -> None:
    subject = uuid.uuid4()
    hold = place_audit_identity_hold(
        reference="LEGAL-2026-014",
        from_day=date(2026, 1, 1),
        to_day=date(2026, 6, 30),
        subject_ref=subject,
        caller=world.holder,
        reason=REASON,
    )
    rows = world.platform.execute(
        "SELECT id, target_id, metadata FROM core.platform_audit_log WHERE action = :a",
        {"a": PLACE},
    )
    assert len(rows) == 1
    audit_id, target_id, metadata = rows[0]
    assert audit_id == hold.platform_audit_id
    assert target_id == str(hold.hold_id)
    assert metadata["reference"] == "LEGAL-2026-014"
    assert metadata["subject_ref"] == str(subject)
    assert metadata["from_day"] == "2026-01-01" and metadata["to_day"] == "2026-06-30"
    stored = world.platform.execute(
        "SELECT placed_by_platform_audit_id, released_at FROM core.platform_audit_identity_holds "
        "WHERE id = :h",
        {"h": hold.hold_id},
    )
    assert stored == [(hold.platform_audit_id, None)]


def test_a_duplicate_hold_and_a_caller_without_the_permission_are_refused(
    world: World,
) -> None:
    place_audit_identity_hold(reference="LEGAL-1", caller=world.holder, reason=REASON)
    with pytest.raises(AuditIdentityHoldAlreadyActiveError):
        place_audit_identity_hold(reference="LEGAL-1", caller=world.holder, reason=REASON)
    # Another subject under the same matter is a different hold.
    place_audit_identity_hold(
        reference="LEGAL-1", subject_ref=uuid.uuid4(), caller=world.holder, reason=REASON
    )
    with pytest.raises(PlatformNotAuthorizedError):
        place_audit_identity_hold(reference="LEGAL-2", caller=world.reporter, reason=REASON)
    denied = [row["reason"] for row in world.platform.audit(action=PLACE, outcome="denied")]
    assert sorted(denied) == ["hold_already_active", "not_authorized"]
    assert world.platform.scalar("SELECT count(*) FROM core.platform_audit_identity_holds") == 2


def test_a_release_needs_a_live_session_and_happens_once(world: World) -> None:
    hold = place_audit_identity_hold(reference="LEGAL-3", caller=world.holder, reason=REASON)
    with pytest.raises(AuditIdentitySessionEvidenceError):
        release_audit_identity_hold(
            hold.hold_id, caller=world.holder, reason=REASON, session_evidence=None
        )
    stranger = world.platform.operator([P.SECURITY_RETENTION_HOLD_MANAGE])[0]
    with pytest.raises(AuditIdentitySessionEvidenceError):
        release_audit_identity_hold(
            hold.hold_id,
            caller=world.holder,
            reason=REASON,
            session_evidence=world.evidence(stranger),
        )
    released = release_audit_identity_hold(
        hold.hold_id,
        caller=world.holder,
        reason=REASON,
        session_evidence=world.evidence(world.holder),
    )
    assert released.released_at is not None
    with pytest.raises(AuditIdentityHoldAlreadyReleasedError):
        release_audit_identity_hold(
            hold.hold_id,
            caller=world.holder,
            reason=REASON,
            session_evidence=world.evidence(world.holder),
        )
    stored = world.platform.execute(
        "SELECT released_by_platform_audit_id FROM core.platform_audit_identity_holds "
        "WHERE id = :h",
        {"h": hold.hold_id},
    )
    assert stored == [(released.platform_audit_id,)]
    page = list_audit_identity_holds(caller=world.holder, active=False)
    assert [h.id for h in page.holds] == [hold.hold_id]


def test_the_database_refuses_a_hold_without_its_audit_evidence(world: World) -> None:
    with pytest.raises(DBAPIError) as refused:
        world.platform.execute(
            "INSERT INTO core.platform_audit_identity_holds (id, reference, "
            "placed_by_platform_audit_id) VALUES (:i, 'LEGAL-4', :a)",
            {"i": uuid.uuid4(), "a": uuid.uuid4()},
        )
    assert getattr(refused.value.orig, "sqlstate", None) == "23503"
    hold = place_audit_identity_hold(reference="LEGAL-5", caller=world.holder, reason=REASON)
    # A release that names an audit row of another act is refused.
    with pytest.raises(DBAPIError) as refused_release:
        world.platform.execute(
            "UPDATE core.platform_audit_identity_holds SET released_at = now(), "
            "released_by_platform_audit_id = placed_by_platform_audit_id WHERE id = :h",
            {"h": hold.hold_id},
        )
    assert getattr(refused_release.value.orig, "sqlstate", None) == "23503"
    release_audit_identity_hold(
        hold.hold_id,
        caller=world.holder,
        reason=REASON,
        session_evidence=world.evidence(world.holder),
    )
    with pytest.raises(DBAPIError) as changed:
        world.platform.execute(
            "UPDATE core.platform_audit_identity_holds SET reference = 'LEGAL-6' WHERE id = :h",
            {"h": hold.hold_id},
        )
    assert getattr(changed.value.orig, "sqlstate", None) == "23514"


# --- the plan --------------------------------------------------------------------------------


def test_the_dry_run_reports_exactly_the_eligible_sets(world: World) -> None:
    now = _now(world)
    a, b, c, d, erased, erased_held = (world.platform.user() for _ in range(6))
    eligible = world.link(a, OLD_DAY)
    eligible_unlinked = world.link(None, OLD_DAY, unlinked=True)
    recent = world.link(b, now.astimezone(UTC).date() - timedelta(days=700))
    referenced_recently = world.link(c, OLD_DAY)
    world.referencing_row(referenced_recently, now - timedelta(days=30))
    in_metadata = world.link(d, OLD_DAY)
    world.referencing_row(in_metadata, now - timedelta(days=30), in_metadata=True)
    referenced_long_ago = world.link(d, OLD_DAY - timedelta(days=1))
    world.referencing_row(referenced_long_ago, now - timedelta(days=900))
    held = world.link(a, OLD_DAY - timedelta(days=2))
    place_audit_identity_hold(
        reference="LEGAL-7", subject_ref=held, caller=world.holder, reason=REASON
    )
    # An erased user with a live link no hold covers any more: unlinked; the
    # marker is old, so it goes once that link is unlinked.
    unheld_live = world.link(erased, now.astimezone(UTC).date())
    world.marker(erased, now - timedelta(days=800))
    # An erased user whose live link is held: the marker stays.
    held_live = world.link(erased_held, now.astimezone(UTC).date() - timedelta(days=1))
    place_audit_identity_hold(
        reference="LEGAL-8", subject_ref=held_live, caller=world.holder, reason=REASON
    )
    world.marker(erased_held, now - timedelta(days=800))

    report = world.dry_run()

    expected = sorted([eligible, eligible_unlinked, referenced_long_ago])
    assert report.eligible_links == 3
    assert report.eligible_links_digest == reference_set_digest("platform", expected)
    assert report.links_to_unlink == 1
    assert report.markers == 1
    holds = world.platform.execute("SELECT id FROM core.platform_audit_identity_holds")
    assert report.active_holds == 2
    assert report.active_holds_digest == hold_set_digest("platform", [h[0] for h in holds])
    assert report.oldest_eligible_day == OLD_DAY - timedelta(days=1)
    assert not report.applied
    # Nothing changed and nothing was recorded by the dry run.
    for ref in (eligible, recent, referenced_recently, in_metadata, held, unheld_live):
        assert world.link_row(ref) is not None
    assert world.platform.audit(action=EXPIRY) == []
    # The application-role report (the scheduled job) sees the same plan.
    job = audit_identity_expiry_report()
    assert {**job.__dict__, "as_of": None} == {**report.__dict__, "as_of": None}


def test_the_application_role_cannot_delete_links_or_markers(world: World) -> None:
    user = world.platform.user()
    world.link(user, OLD_DAY)
    world.marker(user, _now(world) - timedelta(days=800))
    for table in ("core.platform_audit_subject_links", "core.platform_audit_subject_erasures"):
        with pytest.raises(ProgrammingError):  # noqa: PT012 -- one statement in one transaction
            with session_scope() as session:
                session.execute(text(f"DELETE FROM {table}"))  # noqa: S608 -- a fixed name


def test_an_unauthorized_declared_operator_is_refused_with_a_denied_row(world: World) -> None:
    with pytest.raises(PlatformNotAuthorizedError):
        expire_audit_identity_links(caller=world.holder, reason=TICKET)
    assert [row["reason"] for row in world.platform.audit(action=EXPIRY)] == ["not_authorized"]


# --- apply -----------------------------------------------------------------------------------


def test_apply_is_refused_while_the_gate_is_off_and_changes_nothing(world: World) -> None:
    user = world.platform.user()
    ref = world.link(user, OLD_DAY)
    report = world.dry_run()
    with pytest.raises(AuditIdentityExpiryDisabledError):
        expire_audit_identity_links(
            caller=world.reporter,
            reason=TICKET,
            apply=True,
            confirmation=world.confirmation(report),
        )
    assert world.link_row(ref) is not None
    assert world.platform.audit(action=EXPIRY) == []


def test_with_the_gate_on_a_matching_confirmation_expires_and_a_stale_one_changes_nothing(
    world: World, apply_enabled: None
) -> None:
    now = _now(world)
    old, erased = world.platform.user(), world.platform.user()
    eligible = world.link(old, OLD_DAY)
    live_of_erased = world.link(erased, now.astimezone(UTC).date())
    world.marker(erased, now - timedelta(days=800))
    report = world.dry_run()
    assert (report.eligible_links, report.links_to_unlink, report.markers) == (1, 1, 1)

    stale = world.confirmation(report)
    world.link(world.platform.user(), OLD_DAY)  # the eligible set changes
    with pytest.raises(AuditIdentityExpiryConfirmationMismatchError):
        expire_audit_identity_links(
            caller=world.reporter, reason=TICKET, apply=True, confirmation=stale
        )
    assert world.link_row(eligible) is not None
    assert world.link_row(live_of_erased) == (erased, None)
    assert world.markers() == {erased}

    fresh = world.dry_run()
    applied = expire_audit_identity_links(
        caller=world.reporter,
        reason=TICKET,
        apply=True,
        confirmation=world.confirmation(fresh),
    )
    assert applied.applied and applied.run_id is not None
    assert world.link_row(eligible) is None
    assert world.link_row(live_of_erased) == (None, "erasure")
    assert world.markers() == set()
    phases = [
        row["metadata"]["phase"] for row in world.platform.audit(action=EXPIRY, outcome="success")
    ]
    # The refused run left its start row and no finish row (proposal 4.12:
    # a start without a finish identifies a run that did not complete).
    assert phases == ["start", "start", "scope", "finish"]
    scope = next(
        row["metadata"]
        for row in world.platform.audit(action=EXPIRY, outcome="success")
        if row["metadata"]["phase"] == "scope"
    )
    assert scope["links_deleted"] == 2
    assert scope["links_deleted_digest"] == fresh.eligible_links_digest
    assert scope["links_unlinked"] == 1 and scope["markers_deleted"] == 1
    assert [row["reason"] for row in world.platform.audit(action=EXPIRY, outcome="denied")] == [
        "confirmation_mismatch"
    ]
    again = world.dry_run()
    assert (again.eligible_links, again.links_to_unlink, again.markers) == (0, 0, 0)


# --- holds take precedence (D4) ----------------------------------------------------------------


def test_a_held_link_survives_expiry_and_erasure_and_the_first_run_after_release_takes_it(
    world: World, apply_enabled: None
) -> None:
    user = world.platform.user()
    with session_scope() as session:
        today_ref = platform_audit_subject_ref(session, user_id=user)
    old_ref = world.link(user, OLD_DAY)
    hold = place_audit_identity_hold(reference="LEGAL-9", caller=world.holder, reason=REASON)
    with session_scope() as session:
        erasure = erase_platform_audit_subject(session, user_id=user)
    assert erasure.links_unlinked == 0 and erasure.links_kept_under_hold == 2
    report = world.dry_run()
    assert (report.eligible_links, report.links_to_unlink, report.markers) == (0, 0, 0)

    release_audit_identity_hold(
        hold.hold_id,
        caller=world.holder,
        reason=REASON,
        session_evidence=world.evidence(world.holder),
    )
    # Releasing deletes and unlinks nothing by itself.
    assert world.link_row(old_ref) == (user, None)
    after = world.dry_run()
    assert (after.eligible_links, after.links_to_unlink) == (1, 1)
    expire_audit_identity_links(
        caller=world.reporter, reason=TICKET, apply=True, confirmation=world.confirmation(after)
    )
    assert world.link_row(old_ref) is None
    assert world.link_row(today_ref) == (None, "erasure")


# --- erasure markers (O10) ---------------------------------------------------------------------


def test_after_a_marker_expires_a_new_write_links_and_a_re_erasure_makes_a_new_marker(
    world: World, apply_enabled: None
) -> None:
    user = world.platform.user()
    world.marker(user, _now(world) - timedelta(days=800))
    with session_scope() as session:
        before = platform_audit_subject_ref(session, user_id=user)
    assert world.link_row(before) == (None, "erasure")  # born unlinked while the marker exists
    report = world.dry_run()
    assert report.markers == 1
    expire_audit_identity_links(
        caller=world.reporter, reason=TICKET, apply=True, confirmation=world.confirmation(report)
    )
    assert world.markers() == set()
    with session_scope() as session:
        after = platform_audit_subject_ref(session, user_id=user)
    assert world.link_row(after) == (user, None)  # a live link again
    assert world.link_row(before) == (None, "erasure")  # the old reference stays unresolvable

    with session_scope() as session:
        erased = erase_platform_audit_subject(session, user_id=user)
    assert erased.links_unlinked == 1
    assert world.markers() == {user}


def test_a_restored_marker_is_found_again_by_the_next_run(
    world: World, apply_enabled: None
) -> None:
    user = world.platform.user()
    erased_at = _now(world) - timedelta(days=800)
    world.marker(user, erased_at)
    report = world.dry_run()
    expire_audit_identity_links(
        caller=world.reporter, reason=TICKET, apply=True, confirmation=world.confirmation(report)
    )
    assert world.markers() == set()
    world.marker(user, erased_at)  # the restore drill: a backup brings the marker back
    assert world.dry_run().markers == 1


def test_a_recent_marker_is_kept(world: World) -> None:
    user = world.platform.user()
    world.marker(user, _now(world) - timedelta(days=700))
    assert world.dry_run().markers == 0
