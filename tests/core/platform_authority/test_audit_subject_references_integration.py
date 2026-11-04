"""Platform audit subject references against a real PostgreSQL (audit
identity phase P1; owner decisions D1, D6, O2, O6, OD-2 and, of 2026-11-04,
option A1 of docs/architecture/AUDIT-P1-FOREIGN-KEY-OPTIONS.md).

What is asserted, on the stored rows:

- one live reference per user and UTC day, shared by concurrent writers;
- every platform audit row that targets a user (writers W1 to W5 of the
  options paper: the refusal rows of operator enrolment, the user
  operations' refusal, failure and success rows, the attempt and completion
  rows of `resolve_user`, the refused erasure of an enrolled operator) stores
  `target_type = 'user_subject'` and a reference, never the user id, operators
  included; the operator events (PA-3) carry `user_subject_ref` and no
  `user_id`;
- an id that names nobody is recorded as `target_type = 'user'` with no
  target and no link row, a refusal row is still written, and
  `GET`-style `PlatformSubjectNotFoundError` still reaches the caller;
- if the reference cannot be got, the best-effort refusal writer still
  records the denial (no target) and the fail-closed writers raise;
- the platform step of identity erasure, with a hold, a rerun, an unknown id
  and an enrolled operator;
- rows written before the mechanism are untouched.

Marked `integration`; disposable databases only (the `platform` fixture
empties the platform tables, now including the three reference tables).
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from typing import Any

import pytest
from platform_helpers import BOOTSTRAP, REASON, PlatformWorld, join, start
from sqlalchemy.exc import DBAPIError

import saas_os.core.platform_authority.audit as audit
import saas_os.core.platform_authority.subjects as subjects
from saas_os.core.authority import SystemAuthority, SystemCaller, UserCaller
from saas_os.core.identity import resolve_user, revoke_user_sessions
from saas_os.core.identity.erasure import erase_user_identity
from saas_os.core.identity.user_authority import deactivate_user, reactivate_user
from saas_os.core.platform_authority import (
    EnrolledOperatorErasureError,
    PlatformNotAuthorizedError,
    PlatformPermission,
    PlatformSubjectNotFoundError,
    SelfAuthorityChangeError,
    enroll_operator,
    grant_platform_permission,
    reactivate_operator,
    revoke_operator,
    revoke_platform_permission,
    suspend_operator,
)
from saas_os.core.platform_authority.subjects import (
    AuditSubjectLinkUnavailableError,
    erase_platform_audit_subject,
    platform_audit_subject_ref,
    user_audit_target,
    user_exists_for_audit,
)
from saas_os.infra.db import session_scope, tenant_session_scope

pytestmark = pytest.mark.integration

P = PlatformPermission
_READ_ACTION = "platform.user.read"
_ATTEMPT_ACTION = "platform.user.read_attempt"
_UUID_TEXT = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


# --- inspection -------------------------------------------------------------------


def _link(platform: PlatformWorld, ref: str | uuid.UUID) -> dict[str, Any] | None:
    rows = platform.execute(
        "SELECT user_id, subject_day, unlinked_at, unlink_reason "
        "FROM core.platform_audit_subject_links WHERE subject_ref = :r",
        {"r": str(ref)},
    )
    if not rows:
        return None
    return dict(
        zip(("user_id", "subject_day", "unlinked_at", "unlink_reason"), rows[0], strict=True)
    )


def _link_of(platform: PlatformWorld, ref: str | uuid.UUID) -> dict[str, Any]:
    link = _link(platform, ref)
    assert link is not None, f"no link row for {ref}"
    return link


def _live_links(platform: PlatformWorld, user_id: uuid.UUID) -> list[uuid.UUID]:
    return [
        row[0]
        for row in platform.execute(
            "SELECT subject_ref FROM core.platform_audit_subject_links WHERE user_id = :u",
            {"u": user_id},
        )
    ]


def _link_count(platform: PlatformWorld) -> int:
    return platform.scalar("SELECT count(*) FROM core.platform_audit_subject_links")


def _utc_today(platform: PlatformWorld) -> Any:
    return platform.scalar("SELECT (now() AT TIME ZONE 'UTC')::date")


def _assert_reference_of(platform: PlatformWorld, row: dict[str, Any], user_id: uuid.UUID) -> str:
    """The row stores a reference that today's live link maps to `user_id`
    (and never the id itself); returns the reference."""
    assert row["target_type"] == "user_subject"
    reference = row["target_id"]
    assert reference != str(user_id)
    link = _link(platform, reference)
    assert link is not None and link["user_id"] == user_id
    return reference


def _assert_no_raw_user_id(platform: PlatformWorld, *user_ids: uuid.UUID) -> None:
    """No platform audit row names any of `user_ids` as its target or in its
    metadata (the actor column is the decided exception and is not checked)."""
    for user_id in user_ids:
        hits = platform.execute(
            "SELECT action, target_type FROM core.platform_audit_log "
            "WHERE target_id = :u OR metadata::text LIKE :like",
            {"u": str(user_id), "like": f"%{user_id}%"},
        )
        assert hits == [], f"{user_id} is stored raw by {hits}"


def _hold(
    platform: PlatformWorld, reference: str, *, subject_ref: uuid.UUID | None = None
) -> uuid.UUID:
    hold_id = uuid.uuid4()
    platform.execute(
        "INSERT INTO core.platform_audit_identity_holds "
        "(id, reference, subject_ref, placed_by_platform_audit_id) VALUES (:i, :r, :s, :a)",
        {"i": hold_id, "r": reference, "s": subject_ref, "a": uuid.uuid4()},
    )
    return hold_id


def _unauthorized(platform: PlatformWorld) -> UserCaller:
    """An enrolled operator who holds no permission at all."""
    caller, _ = platform.operator(())
    return caller


# --- get-or-create ------------------------------------------------------------------


def test_a_reference_is_one_per_user_and_utc_day_and_random(platform: PlatformWorld) -> None:
    first, second = platform.user(), platform.user()
    with session_scope() as session:
        a = platform_audit_subject_ref(session, user_id=first)
    with session_scope() as session:
        again = platform_audit_subject_ref(session, user_id=first)
        other = platform_audit_subject_ref(session, user_id=second)
        same_transaction = platform_audit_subject_ref(session, user_id=second)
    assert a == again and other == same_transaction and a != other
    assert str(a) not in (str(first), str(second))
    link = _link(platform, a)
    assert link == {
        "user_id": first,
        "subject_day": _utc_today(platform),
        "unlinked_at": None,
        "unlink_reason": None,
    }
    assert _live_links(platform, first) == [a]
    # Version-4 shape from gen_random_uuid(); nothing is derived from the id.
    assert a.version == 4


def test_a_rolled_back_transaction_leaves_no_link(platform: PlatformWorld) -> None:
    user_id = platform.user()
    with pytest.raises(RuntimeError, match="boom"), session_scope() as session:
        platform_audit_subject_ref(session, user_id=user_id)
        raise RuntimeError("boom")
    assert _live_links(platform, user_id) == []


def test_concurrent_first_writes_of_one_user_get_one_reference(platform: PlatformWorld) -> None:
    user_id = platform.user()
    created = threading.Event()
    release = threading.Event()
    result: dict[str, uuid.UUID] = {}

    def holder() -> None:
        with session_scope() as session:
            result["a"] = platform_audit_subject_ref(session, user_id=user_id)
            created.set()
            assert release.wait(timeout=30)

    def contender() -> uuid.UUID:
        with session_scope() as session:
            return platform_audit_subject_ref(session, user_id=user_id)

    holder_thread, holder_outcome = start(holder, "holder")
    assert created.wait(timeout=30)
    contender_thread, contender_outcome = start(contender, "contender")
    time.sleep(1.0)
    assert contender_thread.is_alive(), "the second writer must wait for the first's commit"
    release.set()
    join(holder_thread)
    join(contender_thread)
    assert "error" not in holder_outcome and "error" not in contender_outcome
    assert contender_outcome["result"] == result["a"]
    assert _live_links(platform, user_id) == [result["a"]]


def test_many_concurrent_writers_agree_and_leave_one_live_link_each(
    platform: PlatformWorld,
) -> None:
    users = [platform.user() for _ in range(6)]
    barrier = threading.Barrier(8)

    def writer() -> dict[uuid.UUID, uuid.UUID]:
        barrier.wait(timeout=30)
        got: dict[uuid.UUID, uuid.UUID] = {}
        for user_id in users:
            with session_scope() as session:
                got[user_id] = platform_audit_subject_ref(session, user_id=user_id)
        return got

    runs = [start(writer, f"w{i}") for i in range(8)]
    for thread, _ in runs:
        join(thread)
    results = []
    for _, outcome in runs:
        assert "error" not in outcome, outcome.get("error")
        results.append(outcome["result"])
    for user_id in users:
        assert len({result[user_id] for result in results}) == 1
        assert len(_live_links(platform, user_id)) == 1


def test_a_tenant_bound_transaction_cannot_reach_the_link_table(platform: PlatformWorld) -> None:
    user_id = platform.user()
    with session_scope() as session:
        reference = platform_audit_subject_ref(session, user_id=user_id)
    with tenant_session_scope(uuid.uuid4()) as session:
        with pytest.raises(DBAPIError):
            platform_audit_subject_ref(session, user_id=user_id)  # refused by the policy
    assert _link(platform, reference) is not None  # and nothing changed


def test_the_runtime_role_holds_the_privilege_the_existence_read_needs(
    platform: PlatformWorld,
) -> None:
    """`SELECT ... FOR KEY SHARE` on `core.users` needs UPDATE privilege on
    it (PostgreSQL maps row locks to it); a future narrowing of the runtime
    role's grant would fail every platform user-target audit write."""
    user_id = platform.user()
    with session_scope() as session:
        assert user_exists_for_audit(session, user_id) is True
        assert user_exists_for_audit(session, uuid.uuid4()) is False
        assert user_audit_target(session, user_id=uuid.uuid4()) == subjects.AuditTarget(
            "user", None
        )


def test_the_existence_read_blocks_a_concurrent_delete_of_the_user(
    platform: PlatformWorld,
) -> None:
    user_id = platform.user()
    locked = threading.Event()
    release = threading.Event()

    def holder() -> None:
        with session_scope() as session:
            assert user_exists_for_audit(session, user_id)
            locked.set()
            assert release.wait(timeout=30)

    thread, outcome = start(holder, "key-share")
    assert locked.wait(timeout=30)
    try:
        with platform.admin.connect() as conn:
            conn.exec_driver_sql("SET lock_timeout = '500ms'")
            with pytest.raises(DBAPIError, match="lock timeout"):
                conn.exec_driver_sql(f"DELETE FROM core.users WHERE id = '{user_id}'")
    finally:
        release.set()
        join(thread)
    assert "error" not in outcome


# --- W1: operator enrolment refusals ---------------------------------------------------


def test_a_refused_enrolment_records_the_target_user_as_a_reference(
    platform: PlatformWorld,
) -> None:
    target = platform.user()
    with pytest.raises(PlatformNotAuthorizedError):
        enroll_operator(target, caller=_unauthorized(platform), reason=REASON)
    (row,) = platform.audit(action="platform.operator.enroll", outcome="denied")
    _assert_reference_of(platform, row, target)
    _assert_no_raw_user_id(platform, target)


def test_a_refused_enrolment_of_an_unknown_id_is_still_recorded_with_no_target(
    platform: PlatformWorld,
) -> None:
    unknown = uuid.uuid4()
    caller = _unauthorized(platform)
    before = _link_count(platform)
    with pytest.raises(PlatformNotAuthorizedError):
        enroll_operator(unknown, caller=caller, reason=REASON)
    (row,) = platform.audit(action="platform.operator.enroll", outcome="denied")
    assert (row["target_type"], row["target_id"]) == ("user", None)
    assert row["reason"] == "not_authorized"
    assert _link_count(platform) == before  # no link for an id that names nobody
    _assert_no_raw_user_id(platform, unknown)


def test_an_operator_who_is_the_target_gets_a_reference_like_anyone_else(
    platform: PlatformWorld,
) -> None:
    caller, _ = platform.owner()
    with pytest.raises(SelfAuthorityChangeError):  # a refused enrolment naming the caller
        enroll_operator(caller.user_id, caller=caller, reason=REASON)
    (row,) = platform.audit(action="platform.operator.enroll", outcome="denied")
    _assert_reference_of(platform, row, caller.user_id)
    _assert_no_raw_user_id(platform, caller.user_id)


# --- W2 and W4: user operations ---------------------------------------------------------


def test_user_operations_record_the_reference_in_success_and_refusal_rows(
    platform: PlatformWorld,
) -> None:
    operator, _ = platform.operator((P.SESSION_REVOKE, P.USER_DEACTIVATE, P.USER_REACTIVATE))
    target = platform.user()
    revoke_user_sessions(target, caller=operator, reason=REASON)
    deactivate_user(target, caller=operator, reason=REASON)
    reactivate_user(target, caller=operator, reason=REASON)
    with pytest.raises(PlatformNotAuthorizedError):
        revoke_user_sessions(target, caller=_unauthorized(platform), reason=REASON)
    rows = [
        r for r in platform.audit() if r["action"].startswith(("platform.session", "platform.user"))
    ]
    assert {r["action"] for r in rows} == {
        "platform.session.revoke",
        "platform.user.deactivate",
        "platform.user.reactivate",
    }
    assert {r["outcome"] for r in rows} == {"success", "denied"}
    references = {_assert_reference_of(platform, row, target) for row in rows}
    assert len(references) == 1  # one reference for the user on this UTC day
    _assert_no_raw_user_id(platform, target)


def test_a_user_operation_on_an_operator_target_records_a_reference(
    platform: PlatformWorld,
) -> None:
    actor, _ = platform.operator((P.SESSION_REVOKE,))
    target_operator, _ = platform.operator(())
    revoke_user_sessions(target_operator.user_id, caller=actor, reason=REASON)
    (row,) = platform.audit(action="platform.session.revoke", outcome="success")
    _assert_reference_of(platform, row, target_operator.user_id)


def test_an_unknown_user_is_not_found_recorded_with_no_target_and_no_link(
    platform: PlatformWorld,
) -> None:
    operator, _ = platform.operator((P.SESSION_REVOKE,))
    unknown = uuid.uuid4()
    before = _link_count(platform)
    with pytest.raises(PlatformSubjectNotFoundError):
        revoke_user_sessions(unknown, caller=operator, reason=REASON)
    (row,) = platform.audit(action="platform.session.revoke", outcome="denied")
    assert (row["target_type"], row["target_id"], row["reason"]) == ("user", None, "user_not_found")
    assert _link_count(platform) == before
    _assert_no_raw_user_id(platform, unknown)


# --- W3: resolve_user ----------------------------------------------------------------


def test_resolve_user_records_attempt_and_completion_with_the_same_reference(
    platform: PlatformWorld,
) -> None:
    operator, _ = platform.operator((P.USER_READ,))
    target = platform.user()
    assert resolve_user(caller=operator, user_id=target).id == target
    (attempt,) = platform.audit(action=_ATTEMPT_ACTION)
    (completion,) = platform.audit(action=_READ_ACTION)
    reference = _assert_reference_of(platform, attempt, target)
    assert _assert_reference_of(platform, completion, target) == reference
    _assert_no_raw_user_id(platform, target)


def test_resolve_user_of_an_unknown_id_is_a_404_with_both_rows_and_no_target(
    platform: PlatformWorld,
) -> None:
    operator, _ = platform.operator((P.USER_READ,))
    unknown = uuid.uuid4()
    before = _link_count(platform)
    with pytest.raises(PlatformSubjectNotFoundError):
        resolve_user(caller=operator, user_id=unknown)
    (attempt,) = platform.audit(action=_ATTEMPT_ACTION)
    (completion,) = platform.audit(action=_READ_ACTION)
    for row in (attempt, completion):
        assert (row["target_type"], row["target_id"]) == ("user", None)
    assert completion["metadata"]["returned"] == 0
    assert _link_count(platform) == before
    _assert_no_raw_user_id(platform, unknown)


def test_resolve_user_by_external_identity_records_the_found_user_as_a_reference(
    platform: PlatformWorld,
) -> None:
    operator, _ = platform.operator((P.USER_READ,))
    target = platform.user()
    issuer, subject = (
        platform.scalar(
            "SELECT issuer FROM core.external_identities WHERE user_id = :u", {"u": target}
        ),
        platform.scalar(
            "SELECT subject FROM core.external_identities WHERE user_id = :u", {"u": target}
        ),
    )
    assert resolve_user(caller=operator, issuer=issuer, subject=subject).id == target
    (attempt,) = platform.audit(action=_ATTEMPT_ACTION)
    (completion,) = platform.audit(action=_READ_ACTION)
    assert (attempt["target_type"], attempt["target_id"]) == ("user", None)  # nothing known yet
    _assert_reference_of(platform, completion, target)


def test_an_unauthorized_resolve_is_refused_with_a_reference_and_no_attempt_row(
    platform: PlatformWorld,
) -> None:
    target = platform.user()
    with pytest.raises(PlatformNotAuthorizedError):
        resolve_user(caller=_unauthorized(platform), user_id=target)
    assert platform.audit(action=_ATTEMPT_ACTION) == []
    (row,) = platform.audit(action=_READ_ACTION, outcome="denied")
    _assert_reference_of(platform, row, target)


# --- W5: refused erasure of an enrolled operator ----------------------------------------


def test_the_refused_erasure_of_an_enrolled_operator_records_a_reference_and_keeps_links(
    platform: PlatformWorld,
) -> None:
    operator, _ = platform.operator((P.USER_READ,))
    actor = platform.user()
    with session_scope() as session:  # a live reference exists before the erasure
        reference = platform_audit_subject_ref(session, user_id=operator.user_id)
    with pytest.raises(EnrolledOperatorErasureError):
        erase_user_identity(operator.user_id, (), actor_user_id=actor)
    (row,) = platform.audit(action="platform.user.erase", outcome="denied")
    assert _assert_reference_of(platform, row, operator.user_id) == str(reference)
    assert _link_of(platform, reference)["user_id"] == operator.user_id  # still live
    assert platform.scalar("SELECT count(*) FROM core.platform_audit_subject_erasures") == 0


# --- PA-3: operator events -------------------------------------------------------------------


def test_operator_events_carry_a_subject_reference_and_no_user_id(
    platform: PlatformWorld,
) -> None:
    owner, _ = platform.owner()
    target_user = platform.user()
    operator = enroll_operator(target_user, caller=owner, reason=REASON)
    suspend_operator(operator.id, caller=owner, reason=REASON)
    reactivate_operator(operator.id, caller=owner, reason=REASON)
    grant_platform_permission(operator.id, P.USER_READ, caller=owner, reason=REASON)
    revoke_platform_permission(operator.id, P.USER_READ, caller=owner, reason=REASON)
    revoke_operator(operator.id, caller=owner, reason=REASON)
    actions = {
        "platform.operator.enroll",
        "platform.operator.suspend",
        "platform.operator.reactivate",
        "platform.grant.create",
        "platform.grant.revoke",
        "platform.operator.revoke",
    }
    rows = [
        r
        for r in platform.audit(outcome="success")
        if r["action"] in actions and r["target_id"] == str(operator.id)
    ]
    assert {r["action"] for r in rows} == actions
    references = set()
    for row in rows:
        assert row["target_type"] == "platform_operator"
        assert "user_id" not in row["metadata"]
        reference = row["metadata"]["user_subject_ref"]
        assert re.fullmatch(_UUID_TEXT, reference)
        assert _link_of(platform, reference)["user_id"] == target_user
        references.add(reference)
    assert len(references) == 1  # one reference for the user on this UTC day
    _assert_no_raw_user_id(platform, target_user)


# --- the fallback and the fail-closed writers ------------------------------------------------


def test_the_refusal_writer_still_records_the_denial_when_the_reference_fails(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = platform.user()

    def failing(_session: object, *, user_id: uuid.UUID) -> Any:
        raise AuditSubjectLinkUnavailableError("three collisions")

    monkeypatch.setattr(audit, "user_audit_target", failing)
    assert audit.record_platform_refusal(
        caller=BOOTSTRAP,
        action="platform.user.read",
        target_type="user",
        target_user_id=target,
        code="not_authorized",
    )
    (row,) = platform.audit(outcome="denied")
    assert (row["target_type"], row["target_id"], row["reason"]) == ("user", None, "not_authorized")
    _assert_no_raw_user_id(platform, target)


def test_the_refusal_writer_falls_back_when_the_transaction_is_not_read_committed(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = platform.user()
    monkeypatch.setattr(subjects, "current_transaction_isolation", lambda _s: "serializable")
    assert audit.record_platform_refusal(
        caller=BOOTSTRAP,
        action="platform.user.read",
        target_type="user",
        target_user_id=target,
        code="not_authorized",
    )
    (row,) = platform.audit(outcome="denied")
    assert (row["target_type"], row["target_id"]) == ("user", None)
    assert _live_links(platform, target) == []


def test_the_fail_closed_event_writer_raises_and_leaves_no_row_when_the_reference_fails(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = platform.user()
    monkeypatch.setattr(subjects, "current_transaction_isolation", lambda _s: "serializable")
    with pytest.raises(AuditSubjectLinkUnavailableError), session_scope() as session:
        audit.record_platform_event_in_transaction(
            session,
            caller=BOOTSTRAP,
            action="platform.user.read",
            target_type="user",
            target_user_id=target,
        )
    assert platform.audit_count() == 0


def test_the_fail_closed_attempt_writer_commits_nothing_when_the_reference_fails(
    platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    operator, _ = platform.operator((P.USER_READ,))
    target = platform.user()
    platform.clear_audit()
    monkeypatch.setattr(subjects, "current_transaction_isolation", lambda _s: "serializable")
    with pytest.raises(AuditSubjectLinkUnavailableError):
        audit.record_oversight_attempt(
            caller=operator, operation="user.read", target_type="user", target_user_id=target
        )
    assert platform.audit_count() == 0  # nothing was read either: the caller must not proceed


def test_a_raw_user_target_is_refused_before_any_insert(platform: PlatformWorld) -> None:
    target = platform.user()
    with pytest.raises(Exception, match="reference"), session_scope() as session:
        audit.record_platform_event_in_transaction(
            session,
            caller=BOOTSTRAP,
            action="platform.user.read",
            target_type="user",
            target_id=str(target),
        )
    assert platform.audit_count() == 0


# --- erasure ---------------------------------------------------------------------------------


def _linked_and_written(platform: PlatformWorld) -> tuple[uuid.UUID, uuid.UUID, str]:
    """A user with one live reference stored in a refusal row. Returns
    `(user_id, actor_user_id, reference)`."""
    user_id, actor = platform.user(), platform.user()
    with pytest.raises(PlatformNotAuthorizedError):
        enroll_operator(user_id, caller=_unauthorized(platform), reason=REASON)
    (row,) = platform.audit(action="platform.operator.enroll", outcome="denied")
    return user_id, actor, _assert_reference_of(platform, row, user_id)


def test_erasure_unlinks_the_live_references_and_a_later_write_is_born_unlinked(
    platform: PlatformWorld,
) -> None:
    user_id, actor, reference = _linked_and_written(platform)
    audit_before = platform.audit(outcome="denied")
    result = erase_user_identity(user_id, (), actor_user_id=actor)
    assert (result.platform_references_unlinked, result.platform_references_kept_under_hold) == (
        1,
        0,
    )
    link = _link_of(platform, reference)
    assert link["user_id"] is None and link["unlink_reason"] == "erasure"
    assert link["unlinked_at"] is not None
    assert platform.audit(outcome="denied") == audit_before  # the audit row never changes
    assert (
        platform.scalar(
            "SELECT count(*) FROM core.platform_audit_subject_erasures WHERE user_id = :u",
            {"u": user_id},
        )
        == 1
    )
    # A later write for the erased user gets a reference that names nobody.
    with pytest.raises(PlatformNotAuthorizedError):
        enroll_operator(user_id, caller=_unauthorized(platform), reason=REASON)
    later = platform.audit(action="platform.operator.enroll", outcome="denied")[-1]
    assert later["target_type"] == "user_subject" and later["target_id"] != reference
    born = _link_of(platform, later["target_id"])
    assert born["user_id"] is None and born["unlink_reason"] == "erasure"
    assert _live_links(platform, user_id) == []
    _assert_no_raw_user_id(platform, user_id)


def test_erasure_is_idempotent_and_a_rerun_changes_nothing(platform: PlatformWorld) -> None:
    user_id, actor, reference = _linked_and_written(platform)
    erase_user_identity(user_id, (), actor_user_id=actor)
    snapshot = _link(platform, reference)
    again = erase_user_identity(user_id, (), actor_user_id=actor)
    assert (again.platform_references_unlinked, again.platform_references_kept_under_hold) == (0, 0)
    assert _link(platform, reference) == snapshot
    assert platform.scalar("SELECT count(*) FROM core.platform_audit_subject_erasures") == 1


def test_a_hold_keeps_the_link_live_until_the_first_run_after_its_release(
    platform: PlatformWorld,
) -> None:
    user_id, actor, reference = _linked_and_written(platform)
    hold_id = _hold(platform, "LEGAL-1")  # a scope-wide hold
    result = erase_user_identity(user_id, (), actor_user_id=actor)
    assert (result.platform_references_unlinked, result.platform_references_kept_under_hold) == (
        0,
        1,
    )
    assert _link_of(platform, reference)["user_id"] == user_id  # kept live
    assert platform.scalar("SELECT count(*) FROM core.platform_audit_subject_erasures") == 1
    platform.execute(
        "UPDATE core.platform_audit_identity_holds SET released_at = now(), "
        "released_by_platform_audit_id = :a WHERE id = :h",
        {"a": uuid.uuid4(), "h": hold_id},
    )
    after = erase_user_identity(user_id, (), actor_user_id=actor)
    assert after.platform_references_unlinked == 1  # the marker remained
    assert _link_of(platform, reference)["user_id"] is None


def test_a_hold_on_another_reference_or_day_does_not_cover_the_link(
    platform: PlatformWorld,
) -> None:
    user_id, actor, reference = _linked_and_written(platform)
    _hold(platform, "LEGAL-OTHER", subject_ref=uuid.uuid4())
    platform.execute(
        "INSERT INTO core.platform_audit_identity_holds (id, reference, from_day, to_day, "
        "placed_by_platform_audit_id) VALUES (:i, 'LEGAL-OLD', DATE '2000-01-01', "
        "DATE '2000-12-31', :a)",
        {"i": uuid.uuid4(), "a": uuid.uuid4()},
    )
    result = erase_user_identity(user_id, (), actor_user_id=actor)
    assert result.platform_references_unlinked == 1
    assert _link_of(platform, reference)["user_id"] is None


def test_erasure_of_an_unknown_id_changes_nothing_and_reveals_nothing(
    platform: PlatformWorld,
) -> None:
    actor = platform.user()
    result = erase_user_identity(uuid.uuid4(), (), actor_user_id=actor)
    assert (result.platform_references_unlinked, result.platform_references_kept_under_hold) == (
        0,
        0,
    )
    assert platform.scalar("SELECT count(*) FROM core.platform_audit_subject_erasures") == 0


def test_a_writer_that_commits_first_is_unlinked_and_one_that_waits_sees_the_marker(
    platform: PlatformWorld,
) -> None:
    user_id = platform.user()
    holding = threading.Event()
    release = threading.Event()
    written: dict[str, uuid.UUID] = {}

    def writer() -> None:
        with session_scope() as session:
            written["ref"] = platform_audit_subject_ref(session, user_id=user_id)
            holding.set()
            assert release.wait(timeout=30)

    def erasure() -> Any:
        with session_scope() as session:
            return erase_platform_audit_subject(session, user_id=user_id)

    writer_thread, writer_outcome = start(writer, "writer")
    assert holding.wait(timeout=30)
    erasure_thread, erasure_outcome = start(erasure, "erasure")
    time.sleep(1.0)
    assert erasure_thread.is_alive(), "the erasure must wait for the writer holding S shared"
    release.set()
    join(writer_thread)
    join(erasure_thread)
    assert "error" not in writer_outcome and "error" not in erasure_outcome
    assert erasure_outcome["result"].links_unlinked == 1  # the writer's link was unlinked
    assert _link_of(platform, written["ref"])["user_id"] is None
    # A writer arriving after the erasure sees the marker.
    with session_scope() as session:
        later = platform_audit_subject_ref(session, user_id=user_id)
    assert later != written["ref"] and _link_of(platform, later)["user_id"] is None


# --- rows written before the mechanism ------------------------------------------------------


def test_existing_audit_rows_are_never_rewritten(platform: PlatformWorld) -> None:
    user_id = platform.user()
    legacy = uuid.uuid4()
    platform.execute(
        "INSERT INTO core.platform_audit_log (id, actor_type, system_authority, action, "
        "target_type, target_id, outcome) VALUES (:i, 'system', 'platform_bootstrap', "
        "'platform.user.read', 'user', :t, 'success')",
        {"i": legacy, "t": str(user_id)},
    )
    fingerprint = "SELECT md5(t::text) FROM core.platform_audit_log t WHERE id = :i"
    before = platform.scalar(fingerprint, {"i": legacy})
    operator, _ = platform.operator((P.SESSION_REVOKE, P.USER_READ))
    revoke_user_sessions(user_id, caller=operator, reason=REASON)
    resolve_user(caller=operator, user_id=user_id)
    erase_user_identity(user_id, (), actor_user_id=platform.user())
    assert platform.scalar(fingerprint, {"i": legacy}) == before
    # The legacy exception stays: its raw id is still there (decision D5).
    assert platform.scalar(
        "SELECT target_id FROM core.platform_audit_log WHERE id = :i", {"i": legacy}
    ) == str(user_id)


def test_a_system_caller_can_still_record_user_targets_through_the_same_path(
    platform: PlatformWorld,
) -> None:
    target = platform.user()
    caller = SystemCaller(SystemAuthority.PLATFORM_BOOTSTRAP)
    with session_scope() as session:
        entry = audit.record_platform_event_in_transaction(
            session,
            caller=caller,
            action="platform.user.read",
            target_type="user",
            target_user_id=target,
        )
        recorded = (entry.target_type, entry.target_id)
    assert recorded[0] == "user_subject" and recorded[1] != str(target)
