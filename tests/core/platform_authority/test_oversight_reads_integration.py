"""The oversight reads added for the platform routes, against a real
PostgreSQL (ADR-0045 sections 4, 8 and 9d): user resolution, operators and
grants, the platform audit table, the flag catalog and one tenant's flag
overrides.

Each is gated by exactly one permission, returns a fixed projection, and
is audited by two rows -- the attempt, committed before anything is read,
and the completion. The first half of this file asserts that contract for
all six functions at once; the second half asserts what each one returns.

Marked `integration`. Disposable databases only.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from phase_c_helpers import BILLING, PROVISIONING, REASON, TENANT_PURGE, P, Scene
from platform_helpers import BOOTSTRAP, PlatformWorld
from sqlalchemy import text

import saas_os.core.feature_flags.service as flag_service
import saas_os.core.platform_authority.audit as platform_audit
import saas_os.core.platform_authority.oversight as platform_oversight
from saas_os.core.authority import CallerTypeError, ServiceAccountCaller, UserCaller
from saas_os.core.feature_flags import (
    create_flag,
    read_flag_catalog,
    read_tenant_flag_overrides,
    set_tenant_override,
)
from saas_os.core.identity import resolve_user
from saas_os.core.identity.service import get_or_create_user_for_external_identity
from saas_os.core.platform_authority import (
    InvalidPlatformRequestError,
    OversightReadTimeoutError,
    PlatformNotAuthorizedError,
    PlatformSubjectNotFoundError,
    UserNotResolvedError,
    get_oversight_read_config,
    list_platform_audit,
    list_platform_grants,
    list_platform_operators,
    reactivate_operator,
    revoke_operator,
    revoke_platform_permission,
    suspend_operator,
)
from saas_os.core.tenancy import TenantNotFoundError, TenantStatus, transition_tenant_status

pytestmark = pytest.mark.integration

_ISSUER = "https://issuer.oversight.test"
_READS = ("operators", "grants", "audit", "user", "catalog", "overrides")
_PERMISSION = {
    "operators": P.OPERATOR_READ,
    "grants": P.OPERATOR_READ,
    "audit": P.AUDIT_READ,
    "user": P.USER_READ,
    "catalog": P.FEATURE_FLAG_READ,
    "overrides": P.FEATURE_FLAG_READ,
}
_ACTION = {
    "operators": "platform.operator.read",
    "grants": "platform.operator.read",
    "audit": "platform.audit.read",
    "user": "platform.user.read",
    "catalog": "platform.feature_flag.read",
    "overrides": "platform.feature_flag.read",
}
_PAGED = ("operators", "grants", "audit", "catalog", "overrides")


class World:
    """One subject of every read: a user with a session, a tenant with one
    flag override, and the flag."""

    def __init__(self, scene: Scene, platform: PlatformWorld) -> None:
        self.scene, self.platform = scene, platform
        self.subject = platform.user()
        scene.session_for(self.subject)
        self.tenant = scene.tenant(active=True)
        self.flags: list[str] = []
        self.flag = self.new_flag()
        setter, _ = platform.operator([P.FEATURE_FLAG_OVERRIDE])
        self.setter = setter
        set_tenant_override(self.tenant, self.flag, True, caller=setter, reason=REASON)

    def new_flag(self) -> str:
        key = f"oversight.{uuid.uuid4().hex[:12]}"
        create_flag(key, caller=PROVISIONING)
        self.flags.append(key)
        return key

    def call(self, read: str, caller: Any, **kwargs: Any) -> Any:
        if read == "operators":
            return list_platform_operators(caller=caller, **kwargs)
        if read == "grants":
            return list_platform_grants(caller=caller, **kwargs)
        if read == "audit":
            return list_platform_audit(caller=caller, **kwargs)
        if read == "user":
            return resolve_user(caller=caller, user_id=self.subject, **kwargs)
        if read == "catalog":
            return read_flag_catalog(caller=caller, **kwargs)
        return read_tenant_flag_overrides(self.tenant, caller=caller, **kwargs)

    def cleanup(self) -> None:
        execute = self.platform.execute
        execute(
            "DELETE FROM core.feature_flag_tenant_overrides WHERE flag_id IN "
            "(SELECT id FROM core.feature_flags WHERE key = ANY(:k))",
            {"k": self.flags},
        )
        execute("DELETE FROM core.feature_flags WHERE key = ANY(:k)", {"k": self.flags})
        execute("DELETE FROM core.external_identities WHERE issuer = :i", {"i": _ISSUER})


@pytest.fixture
def world(scene: Scene, platform: PlatformWorld) -> Iterator[World]:
    built = World(scene, platform)
    try:
        yield built
    finally:
        built.cleanup()


def _reader(platform: PlatformWorld, read: str) -> tuple[UserCaller, uuid.UUID]:
    reader, operator_id = platform.operator([_PERMISSION[read]])
    platform.clear_audit()
    return reader, operator_id


def _rows(platform: PlatformWorld, action: str) -> list[dict[str, Any]]:
    return [
        {
            "id": row[0],
            "outcome": row[1],
            "metadata": row[2],
            "target_id": row[3],
            "actor": row[4],
            "reason": row[5],
            "target_tenant_id": row[6],
        }
        for row in platform.execute(
            "SELECT id, outcome, metadata, target_id, actor_user_id, reason, target_tenant_id "
            "FROM core.platform_audit_log WHERE action = :a ORDER BY created_at, id",
            {"a": action},
        )
    ]


def _attempts(platform: PlatformWorld, read: str) -> list[dict[str, Any]]:
    return _rows(platform, _ACTION[read] + "_attempt")


def _completions(platform: PlatformWorld, read: str) -> list[dict[str, Any]]:
    return [row for row in _rows(platform, _ACTION[read]) if row["outcome"] == "success"]


# --- the contract, for every read --------------------------------------------------------


@pytest.mark.parametrize("read", _READS)
def test_a_read_leaves_an_attempt_and_a_completion_that_names_it(
    world: World, platform: PlatformWorld, read: str
) -> None:
    reader, _ = _reader(platform, read)

    world.call(read, reader)

    (attempt,) = _attempts(platform, read)
    (completion,) = _completions(platform, read)
    assert attempt["outcome"] == "success" and attempt["actor"] == reader.user_id
    assert completion["actor"] == reader.user_id
    assert completion["metadata"]["attempt_id"] == str(attempt["id"])
    assert isinstance(completion["metadata"]["returned"], int)
    assert set(completion["metadata"]) == {"attempt_id", "returned"}  # never a value
    assert platform.audit_count() == 2


@pytest.mark.parametrize("read", _READS)
def test_the_attempt_is_committed_before_the_read_transaction_opens(
    world: World, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    reader, _ = _reader(platform, read)
    seen: list[int] = []
    real = platform_oversight.session_scope

    @contextmanager
    def scope() -> Iterator[Any]:
        # A second connection sees a row only once it is committed.
        seen.append(len(_attempts(platform, read)))
        with real() as session:
            yield session

    monkeypatch.setattr(platform_oversight, "session_scope", scope)
    world.call(read, reader)
    assert seen == [1]


@pytest.mark.parametrize("read", _READS)
def test_every_other_permission_is_refused_and_reads_nothing(
    world: World, platform: PlatformWorld, read: str
) -> None:
    """One permission implies no other: an operator holding every platform
    permission except the read's own is refused."""
    others = [permission for permission in P if permission is not _PERMISSION[read]]
    operator, _ = platform.operator(others)
    platform.clear_audit()

    with pytest.raises(PlatformNotAuthorizedError):
        world.call(read, operator)

    assert _attempts(platform, read) == [] and _completions(platform, read) == []
    (denied,) = _rows(platform, _ACTION[read])
    assert denied["outcome"] == "denied" and denied["reason"] == "not_authorized"
    assert denied["actor"] == operator.user_id


@pytest.mark.parametrize("read", _READS)
def test_no_one_but_an_operator_with_the_permission_can_read(
    world: World, platform: PlatformWorld, read: str
) -> None:
    stranger = UserCaller(platform.user())
    tenant_admin, _ = world.scene.admin(world.tenant)
    service_account = ServiceAccountCaller(uuid.uuid4(), world.tenant)
    for caller in (stranger, tenant_admin, service_account, PROVISIONING, BILLING, TENANT_PURGE):
        with pytest.raises(PlatformNotAuthorizedError):
            world.call(read, caller)
    with pytest.raises(PlatformNotAuthorizedError):
        world.call(read, BOOTSTRAP)
    for not_a_caller in (None, stranger.user_id, "operator"):
        with pytest.raises(CallerTypeError):
            world.call(read, not_a_caller)
    if read in _PAGED:
        # The caller is judged before the request: a malformed request
        # from no caller at all is still a caller error.
        with pytest.raises(CallerTypeError):
            world.call(read, None, limit=10_000)
        with pytest.raises(PlatformNotAuthorizedError):
            world.call(read, service_account, limit=10_000)
    assert _attempts(platform, read) == [] and _completions(platform, read) == []


@pytest.mark.parametrize("read", _READS)
def test_a_suspended_or_revoked_operator_cannot_read(
    world: World, platform: PlatformWorld, read: str
) -> None:
    owner, _ = platform.owner()
    reader, operator_id = _reader(platform, read)
    world.call(read, reader)  # while active
    for change in (suspend_operator, reactivate_operator, revoke_operator):
        change(operator_id, caller=owner, reason=REASON)
        platform.clear_audit()
        if change is reactivate_operator:
            world.call(read, reader)  # authority is back, with no grant change
            continue
        with pytest.raises(PlatformNotAuthorizedError):
            world.call(read, reader)
        assert _attempts(platform, read) == []
        (denied,) = _rows(platform, _ACTION[read])
        assert denied["outcome"] == "denied" and denied["actor"] == reader.user_id


@pytest.mark.parametrize("read", _READS)
def test_authority_revoked_between_the_two_transactions_returns_nothing(
    world: World, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    owner, _ = platform.owner()
    reader, operator_id = _reader(platform, read)
    real = platform_oversight.session_scope

    @contextmanager
    def revoke_then_open() -> Iterator[Any]:
        revoke_platform_permission(operator_id, _PERMISSION[read], caller=owner, reason=REASON)
        with real() as session:
            yield session

    monkeypatch.setattr(platform_oversight, "session_scope", revoke_then_open)

    with pytest.raises(PlatformNotAuthorizedError):
        world.call(read, reader)

    assert len(_attempts(platform, read)) == 1  # durable: it was committed first
    assert _completions(platform, read) == []
    assert [row["outcome"] for row in _rows(platform, _ACTION[read])] == ["denied"]


@pytest.mark.parametrize("read", _READS)
def test_a_read_that_fails_returns_nothing_and_leaves_only_its_attempt(
    world: World, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    reader, _ = _reader(platform, read)

    def explode(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("forced completion failure")

    monkeypatch.setattr(platform_oversight, "record_platform_event_in_transaction", explode)

    with pytest.raises(RuntimeError, match="forced completion failure"):
        world.call(read, reader)

    assert len(_attempts(platform, read)) == 1 and _completions(platform, read) == []
    failures = [row for row in _rows(platform, _ACTION[read]) if row["outcome"] == "failure"]
    # Only the read that enters a tenant scope writes a failure row (9d).
    assert len(failures) == (1 if read == "overrides" else 0)


@pytest.mark.parametrize("read", _READS)
def test_the_read_transaction_carries_the_statement_timeout(
    world: World, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    """The lock is taken after the attempt has committed, just before the
    read transaction opens: it is the read that waits and is cancelled."""
    monkeypatch.setenv("PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS", "300")
    get_oversight_read_config.cache_clear()
    reader, _ = _reader(platform, read)
    real = platform_oversight.session_scope
    held = ExitStack()

    @contextmanager
    def lock_then_open() -> Iterator[Any]:
        connection = held.enter_context(platform.admin.connect())
        transaction = connection.begin()
        held.callback(transaction.rollback)
        connection.execute(
            text("SELECT id FROM core.users WHERE id = :u FOR NO KEY UPDATE"),
            {"u": reader.user_id},
        )
        with real() as session:
            yield session

    monkeypatch.setattr(platform_oversight, "session_scope", lock_then_open)
    try:
        with held, pytest.raises(OversightReadTimeoutError) as raised:
            world.call(read, reader)
    finally:
        get_oversight_read_config.cache_clear()

    assert raised.value.stage == "read" and raised.value.timeout_ms == 300
    assert len(_attempts(platform, read)) == 1 and _completions(platform, read) == []
    failures = [row for row in _rows(platform, _ACTION[read]) if row["outcome"] == "failure"]
    # Only the read that enters a tenant scope writes a failure row (9d).
    assert [row["reason"] for row in failures] == (
        ["statement_timeout"] if read == "overrides" else []
    )


@pytest.mark.parametrize("read", _READS)
def test_the_attempt_transaction_carries_the_statement_timeout(
    world: World, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    monkeypatch.setenv("PLATFORM_OVERSIGHT_STATEMENT_TIMEOUT_MS", "300")
    get_oversight_read_config.cache_clear()
    reader, _ = _reader(platform, read)
    connection = platform.admin.connect()
    transaction = connection.begin()
    try:
        connection.execute(
            text("SELECT id FROM core.users WHERE id = :u FOR NO KEY UPDATE"),
            {"u": reader.user_id},
        )
        with pytest.raises(OversightReadTimeoutError) as raised:
            world.call(read, reader)
    finally:
        transaction.rollback()
        connection.close()
        get_oversight_read_config.cache_clear()
    assert raised.value.stage == "attempt" and raised.value.timeout_ms == 300
    assert platform.audit_count() == 0  # nothing happened that evidence could describe


@pytest.mark.parametrize("read", _PAGED)
@pytest.mark.parametrize("limit", [201, 10_000, 0, -1, True, "50", 2.0])
def test_a_page_size_outside_the_limits_is_rejected_never_clamped(
    world: World, platform: PlatformWorld, read: str, limit: Any
) -> None:
    reader, _ = _reader(platform, read)
    with pytest.raises(InvalidPlatformRequestError):
        world.call(read, reader, limit=limit)
    # A flag page is keyed by flag key; every other page by row id.
    bad_cursor: Any = 7 if read in ("catalog", "overrides") else str(uuid.uuid4())
    with pytest.raises(InvalidPlatformRequestError):
        world.call(read, reader, cursor=bad_cursor)
    assert platform.audit_count() == 0  # refused as a request: nothing was attempted
    world.call(read, reader, limit=200)  # the maximum itself is accepted


@pytest.mark.parametrize("read", _READS)
def test_without_authorization_anyone_reads(
    world: World, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    """Negative control: with the two authorization calls removed, the
    stranger the tests above see refused gets the data."""
    stranger = UserCaller(platform.user())
    with pytest.raises(PlatformNotAuthorizedError):
        world.call(read, stranger)
    for module in (platform_audit, platform_oversight):
        monkeypatch.setattr(module, "authorize_platform_caller", lambda *a, **k: None)
    assert world.call(read, stranger) is not None


@pytest.mark.parametrize("read", _READS)
def test_without_the_completion_insert_a_read_returns_data_with_only_an_attempt(
    world: World, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    reader, _ = _reader(platform, read)
    monkeypatch.setattr(
        platform_oversight, "record_platform_event_in_transaction", lambda *a, **k: None
    )
    assert world.call(read, reader) is not None
    assert len(_attempts(platform, read)) == 1 and _completions(platform, read) == []


# --- operators and grants ---------------------------------------------------------------


def _page_through(fetch: Callable[..., Any], attribute: str, **kwargs: Any) -> list[Any]:
    """Every entry, one page of two at a time, by the returned cursor."""
    collected: list[Any] = []
    cursor = None
    for _ in range(200):
        page = fetch(cursor=cursor, limit=2, **kwargs)
        entries = getattr(page, attribute)
        collected.extend(entries)
        if page.next_cursor is None:
            return collected
        assert len(entries) == 2
        cursor = page.next_cursor
    raise AssertionError("pagination did not terminate")


def test_operators_are_listed_in_every_status_with_the_fixed_projection(
    platform: PlatformWorld,
) -> None:
    owner, owner_operator = platform.owner()
    _, suspended = platform.operator([P.TENANT_READ])
    _, revoked = platform.operator([P.TENANT_READ])
    suspend_operator(suspended, caller=owner, reason=REASON)
    revoke_operator(revoked, caller=owner, reason=REASON)

    operators = _page_through(
        lambda **kwargs: list_platform_operators(caller=owner, **kwargs), "operators"
    )

    assert {operator.id: operator.status for operator in operators} == {
        owner_operator: "active",
        suspended: "suspended",
        revoked: "revoked",
    }
    assert [operator.id for operator in operators] == sorted(operator.id for operator in operators)
    assert {field.name for field in dataclasses.fields(operators[0])} == {
        "id",
        "user_id",
        "status",
        "enrolled_by_user_id",
        "status_changed_at",
        "status_changed_by_user_id",
        "created_at",
    }


def test_grants_are_listed_with_revoked_ones_and_can_be_narrowed_to_one_operator(
    platform: PlatformWorld,
) -> None:
    owner, owner_operator = platform.owner()
    _, other = platform.operator([P.TENANT_READ, P.BILLING_READ])
    revoke_platform_permission(other, P.BILLING_READ, caller=owner, reason=REASON)

    def grants(**kwargs: Any) -> list[Any]:
        return _page_through(
            lambda **page: list_platform_grants(caller=owner, **kwargs, **page), "grants"
        )

    of_other = grants(operator_id=other)
    assert {grant.permission: grant.revoked_at is None for grant in of_other} == {
        "platform.tenant:read": True,
        "platform.billing:read": False,  # revoked, and still listed
    }
    assert all(grant.operator_id == other for grant in of_other)
    everything = grants()
    assert len(everything) == len(list(P)) + 2
    assert {grant.operator_id for grant in everything} == {owner_operator, other}
    assert len({grant.id for grant in everything}) == len(everything)  # no page overlap
    assert grants(operator_id=uuid.uuid4()) == []  # no such operator: an empty page
    with pytest.raises(InvalidPlatformRequestError):
        list_platform_grants(caller=owner, operator_id="not-a-uuid")  # type: ignore[arg-type]
    assert {field.name for field in dataclasses.fields(of_other[0])} == {
        "id",
        "operator_id",
        "permission",
        "granted_by_user_id",
        "granted_at",
        "revoked_at",
        "revoked_by_user_id",
    }


# --- the platform audit table --------------------------------------------------------------


def test_the_audit_read_returns_the_rows_as_stored_and_is_itself_audited(
    platform: PlatformWorld,
) -> None:
    reader, _ = platform.operator([P.AUDIT_READ])
    stored = {
        row[0]: row[1:]
        for row in platform.execute(
            "SELECT id, action, outcome, actor_type, target_type, target_id, reason "
            "FROM core.platform_audit_log"
        )
    }
    assert stored  # the enrollment and the grant

    # One page: every call adds two rows to the table it is paging through.
    page = list_platform_audit(caller=reader, limit=200)
    entries = page.entries
    assert page.next_cursor is None
    assert [entry.id for entry in entries] == sorted(entry.id for entry in entries)

    by_id = {entry.id: entry for entry in entries}
    assert len(by_id) == len(entries)  # no page overlap
    for row_id, row in stored.items():
        entry = by_id[row_id]
        assert (
            entry.action,
            entry.outcome,
            entry.actor_type,
            entry.target_type,
            entry.target_id,
            entry.reason,
        ) == row
    # Reading it is recorded in it: the rows of these calls are there for
    # the next reader.
    after = {entry.action for entry in list_platform_audit(caller=reader, limit=200).entries}
    assert {"platform.audit.read", "platform.audit.read_attempt"} <= after


def test_the_audit_read_filters_by_time_actor_action_and_target_tenant(
    world: World, platform: PlatformWorld
) -> None:
    """Section 8. "What did this operator do, to this tenant, since then"
    is one filtered read."""
    owner, _ = platform.owner()
    suspender, _ = platform.operator([P.TENANT_SUSPEND])
    reader, _ = platform.operator([P.AUDIT_READ])
    other_tenant = world.scene.tenant(active=True)
    before = platform.scalar("SELECT now()")
    transition_tenant_status(world.tenant, TenantStatus.SUSPENDED, caller=suspender)
    transition_tenant_status(other_tenant, TenantStatus.SUSPENDED, caller=suspender)
    after = platform.scalar("SELECT now()")

    def actions(**filters: Any) -> list[tuple[str, Any, Any]]:
        page = list_platform_audit(caller=reader, limit=200, **filters)
        assert page.next_cursor is None
        return sorted(
            (entry.action, entry.actor_user_id, entry.target_tenant_id) for entry in page.entries
        )

    suspend = "platform.tenant.suspend"
    assert actions(actor_user_id=suspender.user_id, since=before) == sorted(
        [(suspend, suspender.user_id, other_tenant), (suspend, suspender.user_id, world.tenant)]
    )
    assert actions(target_tenant_id=world.tenant, action=suspend) == [
        (suspend, suspender.user_id, world.tenant)
    ]
    assert actions(action=suspend, since=before, until=after) == actions(
        actor_user_id=suspender.user_id, since=before
    )
    assert actions(action=suspend, until=before) == []  # nothing that early
    assert actions(action=suspend, since=after) == []  # nothing that late
    assert actions(actor_user_id=owner.user_id, action=suspend) == []
    # What was asked for is recorded with the attempt; what was found is not.
    (attempt,) = [
        row
        for row in _attempts(platform, "audit")
        if row["metadata"]["filters"]["target_tenant_id"] == str(world.tenant)
    ]
    assert attempt["metadata"]["filters"] == {
        "since": None,
        "until": None,
        "actor_user_id": None,
        "action": suspend,
        "target_tenant_id": str(world.tenant),
    }


@pytest.mark.parametrize(
    "filters",
    [
        {"since": datetime(2026, 1, 1)},  # no time zone
        {"until": "2026-01-01T00:00:00+00:00"},
        {"since": datetime(2026, 2, 1, tzinfo=UTC), "until": datetime(2026, 1, 1, tzinfo=UTC)},
        {"actor_user_id": "not-a-uuid"},
        {"target_tenant_id": 7},
        {"action": ""},
        {"action": "x" * 201},
        {"action": 5},
    ],
)
def test_an_audit_filter_of_the_wrong_shape_is_rejected(
    platform: PlatformWorld, filters: dict[str, Any]
) -> None:
    reader, _ = _reader(platform, "audit")
    with pytest.raises(InvalidPlatformRequestError):
        list_platform_audit(caller=reader, **filters)
    assert platform.audit_count() == 0


# --- user resolution ---------------------------------------------------------------------


def _external_user(platform: PlatformWorld) -> tuple[uuid.UUID, str]:
    subject = f"subject-{uuid.uuid4().hex}"
    user_id = get_or_create_user_for_external_identity(_ISSUER, subject).id
    platform.users.append(user_id)
    return user_id, subject


def test_a_user_is_resolved_by_id_or_by_external_identity_to_the_same_projection(
    world: World, platform: PlatformWorld
) -> None:
    user_id, subject = _external_user(platform)
    world.scene.session_for(user_id)
    reader, _ = _reader(platform, "user")

    by_id = resolve_user(caller=reader, user_id=user_id)
    by_identity = resolve_user(caller=reader, issuer=_ISSUER, subject=subject)

    assert by_id == by_identity
    assert by_id.id == user_id and by_id.is_active is True
    assert by_id.is_enrolled_operator is False
    assert by_id.live_sessions == 1 and by_id.more_live_sessions is False
    assert len(by_id.sessions) == 1 and by_id.sessions[0].revoked_at is None
    assert {field.name for field in dataclasses.fields(by_id)} == {
        "id",
        "is_active",
        "created_at",
        "is_enrolled_operator",
        "live_sessions",
        "more_live_sessions",
        "sessions",
    }
    assert {field.name for field in dataclasses.fields(by_id.sessions[0])} == {
        "id",
        "created_at",
        "expires_at",
        "revoked_at",
    }
    # Neither the result nor any audit row repeats the external identity.
    evidence = json.dumps(platform.audit(), default=str) + repr(by_identity)
    assert _ISSUER not in evidence and subject not in evidence
    # The lookup by identity names the user it found, in the completion only.
    attempts = _attempts(platform, "user")
    completions = _completions(platform, "user")
    assert [row["target_id"] for row in attempts] == [str(user_id), None]
    assert [row["target_id"] for row in completions] == [str(user_id), str(user_id)]
    assert [row["metadata"] for row in attempts] == [
        {"lookup": "user_id"},
        {"lookup": "external_identity"},
    ]


def test_live_sessions_are_counted_to_fifty_and_the_fifty_most_recent_are_listed(
    world: World, platform: PlatformWorld
) -> None:
    user_id = platform.user()
    for _ in range(53):
        world.scene.session_for(user_id)
    sessions = [
        row[0]
        for row in platform.execute(
            "SELECT id FROM core.sessions WHERE user_id = :u ORDER BY created_at, id",
            {"u": user_id},
        )
    ]
    reader, _ = _reader(platform, "user")

    resolution = resolve_user(caller=reader, user_id=user_id)
    assert (resolution.live_sessions, resolution.more_live_sessions) == (50, True)
    assert len(resolution.sessions) == 50
    created = [session.created_at for session in resolution.sessions]
    assert created == sorted(created, reverse=True)  # most recent first

    # One revoked and one expired: neither is live, both stay listed.
    platform.execute(
        "UPDATE core.sessions SET revoked_at = now() WHERE id = ANY(:s)", {"s": sessions[-2:-1]}
    )
    platform.execute(
        "UPDATE core.sessions SET expires_at = now() - interval '1 minute' WHERE id = ANY(:s)",
        {"s": sessions[-1:]},
    )
    platform.execute("DELETE FROM core.sessions WHERE id = ANY(:s)", {"s": sessions[:3]})
    resolution = resolve_user(caller=reader, user_id=user_id)
    assert (resolution.live_sessions, resolution.more_live_sessions) == (48, False)
    assert len(resolution.sessions) == 50
    assert sum(session.revoked_at is not None for session in resolution.sessions) == 1
    # Exactly fifty live sessions is fifty, and not "more".
    platform.execute(
        "UPDATE core.sessions SET revoked_at = NULL, expires_at = now() + interval '1 hour' "
        "WHERE user_id = :u",
        {"u": user_id},
    )
    resolution = resolve_user(caller=reader, user_id=user_id)
    assert (resolution.live_sessions, resolution.more_live_sessions) == (50, False)


def test_the_operator_flag_follows_the_enrollment(platform: PlatformWorld) -> None:
    owner, _ = platform.owner()
    reader, _ = platform.operator([P.USER_READ])
    subject, operator_id = platform.operator([P.TENANT_READ])
    assert resolve_user(caller=reader, user_id=subject.user_id).is_enrolled_operator is True
    revoke_operator(operator_id, caller=owner, reason=REASON)
    assert resolve_user(caller=reader, user_id=subject.user_id).is_enrolled_operator is False
    platform.set_user_active(subject.user_id, False)
    assert resolve_user(caller=reader, user_id=subject.user_id).is_active is False


def test_an_unknown_user_is_reported_after_both_rows_and_without_the_identity(
    platform: PlatformWorld,
) -> None:
    reader, _ = _reader(platform, "user")
    missing = uuid.uuid4()

    with pytest.raises(PlatformSubjectNotFoundError):
        resolve_user(caller=reader, user_id=missing)
    with pytest.raises(UserNotResolvedError) as raised:
        resolve_user(caller=reader, issuer=_ISSUER, subject="nobody-by-this-name")

    assert _ISSUER not in str(raised.value) and "nobody-by-this-name" not in str(raised.value)
    completions = _completions(platform, "user")
    assert [row["metadata"]["returned"] for row in completions] == [0, 0]
    assert [row["target_id"] for row in completions] == [str(missing), None]
    assert len(_attempts(platform, "user")) == 2
    assert "nobody-by-this-name" not in json.dumps(platform.audit(), default=str)


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"user_id": uuid.uuid4(), "issuer": _ISSUER, "subject": "s"},
        {"issuer": _ISSUER},
        {"subject": "s"},
        {"issuer": "", "subject": "s"},
        {"issuer": _ISSUER, "subject": ""},
        {"user_id": "not-a-uuid"},
        {"issuer": 1, "subject": "s"},
    ],
)
def test_a_lookup_that_is_not_exactly_one_of_the_two_forms_is_rejected(
    platform: PlatformWorld, arguments: dict[str, Any]
) -> None:
    reader, _ = _reader(platform, "user")
    with pytest.raises(InvalidPlatformRequestError):
        resolve_user(caller=reader, **arguments)
    assert platform.audit_count() == 0


# --- feature flags -------------------------------------------------------------------------


def test_the_catalog_read_returns_key_and_default_and_nothing_else(
    world: World, platform: PlatformWorld
) -> None:
    second = world.new_flag()
    reader, _ = _reader(platform, "catalog")

    flags = _page_through(lambda **kwargs: read_flag_catalog(caller=reader, **kwargs), "flags")

    keys = [flag.key for flag in flags]
    assert world.flag in keys and second in keys and len(set(keys)) == len(keys)
    assert all(flag.enabled_by_default is False for flag in flags if flag.key in world.flags)
    assert {field.name for field in dataclasses.fields(flags[0])} == {"key", "enabled_by_default"}


def test_overrides_are_read_for_the_named_tenant_only(
    world: World, platform: PlatformWorld
) -> None:
    other_tenant = world.scene.tenant(active=True)
    second = world.new_flag()
    set_tenant_override(world.tenant, second, False, caller=world.setter, reason=REASON)
    third = world.new_flag()
    set_tenant_override(other_tenant, third, True, caller=world.setter, reason=REASON)
    reader, _ = _reader(platform, "overrides")

    def overrides(tenant: uuid.UUID) -> dict[str, bool]:
        entries = _page_through(
            lambda **kwargs: read_tenant_flag_overrides(tenant, caller=reader, **kwargs),
            "overrides",
        )
        assert {field.name for field in dataclasses.fields(entries[0])} == {"key", "enabled"}
        return {entry.key: entry.enabled for entry in entries}

    assert overrides(world.tenant) == {world.flag: True, second: False}
    assert overrides(other_tenant) == {third: True}
    # The completion names the tenant that was read.
    completions = _completions(platform, "overrides")
    assert {row["target_id"] for row in completions} == {str(world.tenant), str(other_tenant)}
    assert all(str(row["target_tenant_id"]) == row["target_id"] for row in completions)
    # A cursor is a flag key, and a key from another tenant's page opens
    # nothing: it only moves the start within the named tenant's own rows.
    page = read_tenant_flag_overrides(world.tenant, caller=reader, cursor=third)
    assert {entry.key for entry in page.overrides} <= {world.flag, second}


def test_overrides_of_a_suspended_tenant_are_readable_and_an_unknown_tenant_is_an_empty_page(
    world: World, platform: PlatformWorld
) -> None:
    reader, _ = _reader(platform, "overrides")
    world.scene.set_status(world.tenant, TenantStatus.SUSPENDED)
    page = read_tenant_flag_overrides(world.tenant, caller=reader)
    assert [(entry.key, entry.enabled) for entry in page.overrides] == [(world.flag, True)]

    # A tenant with no override: an empty page.
    bare = world.scene.tenant(active=True)
    empty = read_tenant_flag_overrides(bare, caller=reader)
    assert empty.overrides == () and empty.next_cursor is None and empty.tenant_id == bare

    # A tenant that does not exist: both rows, then the error (9d table).
    missing = uuid.uuid4()
    platform.clear_audit()
    with pytest.raises(TenantNotFoundError):
        read_tenant_flag_overrides(missing, caller=reader)
    (attempt,) = _attempts(platform, "overrides")
    (completion,) = _completions(platform, "overrides")
    assert completion["metadata"] == {"attempt_id": str(attempt["id"]), "returned": 0}
    assert completion["target_id"] == str(missing) and completion["target_tenant_id"] is None
    # Without the permission: refused before the lookup, the same for both.
    stranger = UserCaller(platform.user())
    for tenant in (missing, world.tenant):
        with pytest.raises(PlatformNotAuthorizedError):
            read_tenant_flag_overrides(tenant, caller=stranger)
    with pytest.raises(InvalidPlatformRequestError):
        read_tenant_flag_overrides("not-a-uuid", caller=reader)  # type: ignore[arg-type]


def test_without_the_tenant_scope_the_override_read_sees_nothing(
    world: World, platform: PlatformWorld, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: the read reaches the tenant's rows only through
    the pinned scope. With the binding removed, row-level security -- with
    no tenant bound -- returns no row at all, for any tenant."""
    reader, _ = _reader(platform, "overrides")
    assert len(read_tenant_flag_overrides(world.tenant, caller=reader).overrides) == 1

    @contextmanager
    def unbound(session: Any, tenant_id: uuid.UUID) -> Iterator[Any]:
        yield session

    monkeypatch.setattr(flag_service, "bind_tenant_scope", unbound)
    assert read_tenant_flag_overrides(world.tenant, caller=reader).overrides == ()
